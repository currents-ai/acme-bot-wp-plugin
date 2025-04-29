<?php

/**
 * @link              https://acme.bot/
 * @since             1.0.0
 * @package           AcmeBot
 *
 * @wordpress-plugin
 * Plugin Name:     Acme Bot
 * Description:     Acme Bot - AI content assistant for WordPress.
 * Version:         1.0.0 
 * Author:          Acme Bot Team
 * Author URI:      https://acme.bot/
 * License:         GPL-2.0 or later
 * License URI:     http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:     acme.bot
 * Domain Path:     /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}



if (!class_exists('AcmeBot')) {
    /**
     * The core plugin class.
     */
    class AcmeBot
    {
        /**
         * The current version of the REST API.
         * @var int
         */
        const REST_VERSION = 1;

        /**
         * The option name used to store the secret key.
         * @var string
         */
        const SECRET_OPTION = 'acmebot_secret';

        /**
         * Event name for integration creation confirmation.
         * @var string
         */
        const EVENT_INTEGRATION_CREATED = 'integration_created';

        /**
         * Event name for creating a new post via webhook.
         * @var string
         */
        const EVENT_CREATE_POST = 'create_post';

        /**
         * Default User ID to use if none provided or invalid in webhook.
         * Usually ID 1 is the first admin user.
         * @var int
         */
        const DEFAULT_AUTHOR_ID = 1;


        /**
         * The URL for the Acme Bot API authorization.
         * @var string
         */
        const ACMEBOT_API_AUTHORIZE_URL = 'https://acme.bot/api_acme/wp-plugin/authorize';


        const ACMEBOT_API_HOST = 'acme.bot';

        /**
         * Initialize the class and set up hooks.
         */
        public function __construct()
        {
            // Register REST API endpoints
            add_action('rest_api_init', [$this, 'register_rest_route']);

            // Admin specific hooks
            if (is_admin()) {
                // Add settings link on plugin page
                add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
                // Add allowed redirect host for the webhook URL 
                add_filter('allowed_redirect_hosts', [$this, 'add_acmebot_allowed_host']);
                // Add settings page to menu
                add_action('admin_menu', [$this, 'add_plugin_page']);
                // Handle form submission for generating secret/redirecting
                add_action('admin_post_acmebot_handle_form', [$this, 'handle_form_submission']);

                // Redirect to settings page after activation
                add_action('admin_init', [$this, 'admin_init']);

                add_action('admin_notices', [$this, 'display_settings_errors']);

                //Register activation hook to set up the plugin
                register_activation_hook(__FILE__, ['AcmeBot', 'activate']);

                // Register deactivation hook to clean up options
                register_deactivation_hook(__FILE__, [$this, 'deactivate']);
            }
        }

        // Add this inside your main plugin class
        public static function activate()
        {
            // Set a transient to trigger the redirect after activation
            set_transient('acmebot_activation_redirect', true, 30);
        }

        public function admin_init()
        {
            // Check if we should redirect
            if (get_transient('acmebot_activation_redirect')) {
                // Delete the transient so it only happens once
                delete_transient('acmebot_activation_redirect');

                // Make sure it's the proper admin page
                if (!isset($_GET['activate-multi'])) {
                    // Redirect to the settings page
                    wp_safe_redirect(admin_url('options-general.php?page=acme-bot-integration'));
                    exit;
                }
            }
        }

        /**
         * Register the REST API route for the webhook.
         */
        public function register_rest_route(): void
        {
            register_rest_route('acmebot/v' . self::REST_VERSION, '/webhook', [
                'methods' => WP_REST_Server::CREATABLE, // Use constant for POST method
                'callback' => [$this, 'handle_webhook'],
                // Permission callback allows public access, security is handled by checking the secret inside the callback.
                'permission_callback' => '__return_true',
                // Define expected parameters for documentation and potential validation
                'args' => [
                    'event' => [
                        'required' => true,
                        'type' => 'string',
                        'description' => __('The type of event being triggered.', 'acme-bot'),
                    ],
                    'payload' => [
                        'required' => true,
                        'type' => 'object',
                        'description' => __('The data associated with the event.', 'acme-bot'),
                        // Optionally define properties within payload for better documentation/schema
                        'properties' => [
                            'title' => ['type' => 'string'],
                            'content' => ['type' => 'string'],
                            'user_id' => ['type' => 'integer'],
                            'user_name' => ['type' => 'string'],
                            'categories' => ['type' => 'array', 'items' => ['type' => ['string', 'integer']]],
                        ],
                    ],
                ],
            ]);
        }

        /**
         * Handle incoming webhook requests.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function handle_webhook(WP_REST_Request $request): WP_REST_Response
        {
            try {
                // 1. Verify the Secret
                $received_secret = $request->get_header('x-secret');
                $stored_secret = get_option(self::SECRET_OPTION);

                // Ensure both secrets are set and compare them securely
                if (empty($received_secret) || empty($stored_secret) || !hash_equals((string) $stored_secret, (string) $received_secret)) {
                    return new WP_REST_Response(__('Unauthorized', 'acme-bot'), 401);
                }

                // 2. Process the Event
                $event = $request->get_param('event');
                $payload = $request->get_param('payload');

                // Validate required parameters
                if (empty($event)) {
                    return new WP_REST_Response(__('Missing required parameter: event', 'acme-bot'), 400);
                }

                switch ($event) {
                    case self::EVENT_INTEGRATION_CREATED:
                        // Simple success response for integration confirmation
                        return new WP_REST_Response(__('Integration successful', 'acme-bot'), 200);

                    case self::EVENT_CREATE_POST:
                        // Handle post creation with its own try-catch for specific errors
                        return $this->handle_create_post($payload);

                    default:
                        // Event type not recognized
                        return new WP_REST_Response(__('Event not recognized', 'acme-bot'), 400);
                }
            } catch (Exception $e) {
                // Log the full exception for debugging
                error_log('AcmeBot Webhook Error: ' . $e->getMessage() . ' in ' . $e->getFile() . ' on line ' . $e->getLine());

                // Return a controlled error response
                return new WP_REST_Response(
                    sprintf(__('Error processing webhook: %s', 'acme-bot'), $e->getMessage()),
                    500
                );
            }
        }

        /**
         * Handle the create_post event from the webhook.
         * 
         * @param array $payload The payload for the create_post event.
         * @return WP_REST_Response Response object.
         */
        private function handle_create_post($payload): WP_REST_Response
        {
            try {
                // Validate payload structure
                if (!is_array($payload)) {
                    error_log('AcmeBot Webhook: Received non-array payload for create_post. Type: ' . gettype($payload));
                    return new WP_REST_Response(__('Invalid payload: Payload must be an object/associative array.', 'acme-bot'), 400);
                }

                // Get title and content using null coalescing operator for safety
                $title = $payload['title'] ?? null;
                $content = $payload['content'] ?? null;

                // Ensure required fields are present
                if (empty($title) || !isset($content)) { // Allow empty content string, but title must be non-empty
                    return new WP_REST_Response(__('Invalid payload: title is required, content must be present', 'acme-bot'), 400);
                }

                // --- Post Author Handling ---
                $author_id = self::DEFAULT_AUTHOR_ID; // Start with default

                // First check if user_id is provided
                if (isset($payload['user_id']) && is_numeric($payload['user_id'])) {
                    $potential_author_id = absint($payload['user_id']); // Ensure positive integer
                    if ($potential_author_id > 0 && get_user_by('ID', $potential_author_id)) {
                        $author_id = $potential_author_id;
                    } else {
                        error_log('AcmeBot Webhook: Invalid or non-existent user_id provided: ' . $payload['user_id']);
                    }
                }
                // Then check if user_name is provided
                elseif (isset($payload['user_name']) && is_string($payload['user_name']) && !empty(trim($payload['user_name']))) {
                    $username = sanitize_user($payload['user_name']);
                    $user = get_user_by('login', $username);

                    if (!$user) {
                        // Also try to find by display name
                        $users = get_users([
                            'search' => $username,
                            'search_columns' => ['display_name'],
                            'number' => 1
                        ]);

                        if (!empty($users)) {
                            $user = $users[0];
                        }
                    }

                    if ($user && $user->ID > 0) {
                        $author_id = $user->ID;
                    } else {
                        error_log('AcmeBot Webhook: User not found by username: ' . $username);
                    }
                }

                // --- Category Handling ---
                $category_ids = [];
                if (isset($payload['categories']) && is_array($payload['categories'])) {
                    foreach ($payload['categories'] as $category_ref) {
                        $cat_id = 0;

                        if (is_int($category_ref) || is_numeric($category_ref)) {
                            // Assume it's an ID
                            $term = term_exists(absint($category_ref), 'category');
                            if ($term) {
                                $cat_id = (int)$term['term_id'];
                            }
                        } elseif (is_string($category_ref) && !empty(trim($category_ref))) {
                            // Assume it's a name
                            $category_name = sanitize_text_field($category_ref);
                            $term = term_exists($category_name, 'category');
                            if ($term) {
                                $cat_id = (int)$term['term_id'];
                            } else {
                                $new_cat = wp_insert_term($category_name, 'category');
                                if (!is_wp_error($new_cat) && isset($new_cat['term_id'])) {
                                    $cat_id = (int)$new_cat['term_id'];
                                }
                            }
                        }

                        if ($cat_id > 0 && !in_array($cat_id, $category_ids)) {
                            $category_ids[] = $cat_id;
                        }
                    }
                }

                // --- Sanitize and Prepare Post Data ---
                $post_data = [
                    'post_title'   => sanitize_text_field($title),
                    'post_content' => wp_kses_post($content), // Allows safe HTML
                    'post_status'  => 'publish',             // Or 'draft' etc.
                    'post_author'  => $author_id,
                ];

                // Add categories if any were validated
                if (!empty($category_ids)) {
                    $post_data['post_category'] = $category_ids;
                }

                // --- Insert Post ---
                $post_id = wp_insert_post($post_data, true); // Pass true to return WP_Error on failure

                // Check for errors during post creation
                if (is_wp_error($post_id)) {
                    error_log('AcmeBot Error: Failed to create post via webhook. WP_Error: ' . $post_id->get_error_message());
                    return new WP_REST_Response(
                        sprintf(__('Failed to create post: %s', 'acme-bot'), $post_id->get_error_message()),
                        500
                    );
                }

                // Post created successfully
                $post_url = get_permalink($post_id);

                return new WP_REST_Response([
                    'message' => __('Post created successfully', 'acme-bot'),
                    'post_id' => $post_id,
                    'url' => $post_url,
                    'status' => 'SUCCESS',
                ], 200);
            } catch (Exception $e) {
                // Log the error for administrators
                error_log('AcmeBot Error in create_post handler: ' . $e->getMessage() . ' in ' . $e->getFile() . ' on line ' . $e->getLine());

                // Return a server error response
                return new WP_REST_Response(
                    sprintf(__('Error creating post: %s', 'acme-bot'), $e->getMessage()),
                    500
                );
            }
        }
        /**
         * Runs on plugin deactivation.
         * Cleans up the stored secret option.
         */
        public function deactivate(): void
        {
            delete_option(self::SECRET_OPTION);
            // Optionally delete other settings like the integrating user ID if you store it
            // delete_option('acmebot_integrating_user_id');
        }

        /**
         * Handles the form submission from the settings page.
         * Generates a strong secret, saves it, and redirects to the external service for authorization.
         */
        public function handle_form_submission(): void
        {

            // Initialize error messages array
            $errors = [];

            // 1. Verify Nonce for Security
            if (!isset($_POST['acmebot_settings_nonce']) || !wp_verify_nonce(sanitize_key($_POST['acmebot_settings_nonce']), 'acmebot_settings_action')) {
                $errors[] = __('Security verification failed. Please try again.', 'acme-bot');
            }

            // 2. Check Administrator Capabilities
            if (!current_user_can('manage_options')) {
                $errors[] = __('You do not have administrative permissions to perform this action.', 'acme-bot');
            }

            // 3. Check Editing Capabilities
            if (!current_user_can('edit_posts') || !current_user_can('publish_posts')) {
                $errors[] = __('You need to have editing and publishing capabilities to set up this integration.', 'acme-bot');
            }

            // 4. Get Current User ID (The admin setting up the integration)
            $integrating_user_id = get_current_user_id();
            if ($integrating_user_id === 0) {
                $errors[] = __('Could not determine your User ID. Please ensure you are logged in.', 'acme-bot');
            }

            // If we have errors, store them in a transient and redirect back to the settings page
            if (!empty($errors)) {
                set_transient('acmebot_settings_errors', $errors, 60 * 5); // Store for 5 minutes
                wp_safe_redirect(add_query_arg('acmebot_error', '1', admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }

            try {
                // Store this user ID as the default author for posts created via webhook
                update_option('acmebot_default_author_id', $integrating_user_id);

                // Generate and Store Strong Secret
                $secret = wp_generate_password(64, false);
                if (!update_option(self::SECRET_OPTION, $secret)) {
                    throw new Exception(__('Failed to save integration secret.', 'acme-bot'));
                }

                // Prepare Redirect URL
                $webhook_url = esc_url_raw(rest_url('acmebot/v' . self::REST_VERSION . '/webhook'));
                $redirect_url = add_query_arg(
                    [
                        'webhook_url' => urlencode($webhook_url),
                        'secret' => urlencode($secret),
                        'user_id' => urlencode($integrating_user_id)
                    ],
                    self::ACMEBOT_API_AUTHORIZE_URL
                );

                // Redirect User to external authorization page
                wp_safe_redirect($redirect_url);
                exit;
            } catch (Exception $e) {
                // Log the error for debugging
                error_log('Acme Bot Setup Error: ' . $e->getMessage());

                // Store the error message for display
                set_transient('acmebot_settings_errors', [$e->getMessage()], 60 * 5);
                wp_safe_redirect(add_query_arg('acmebot_error', '1', admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }
        }

        /**
         * Add settings action link to the plugins page.
         *
         * @param array $links An array of plugin action links.
         * @return array An array of plugin action links.
         */
        public function add_settings_link(array $links): array
        {
            $settings_link = '<a href="' . esc_url(admin_url('options-general.php?page=acme-bot-integration')) . '">' . esc_html__('Settings', 'acme-bot') . '</a>';
            // Add link to the beginning of the links array
            array_unshift($links, $settings_link);
            return $links;
        }


        /**
         * Add the Acme Bot API host to the list of allowed redirect hosts.
         * This allows wp_safe_redirect() to work with the external authorization URL.
         *
         * @param array $hosts An array of allowed host names.
         * @return array The modified array of allowed host names.
         */
        public function add_acmebot_allowed_host(array $hosts): array
        {
            // Add the specific host defined in the constant
            $hosts[] = self::ACMEBOT_API_HOST;
            return $hosts;
        }

        /**
         * Add options page under the Settings menu.
         */
        public function add_plugin_page(): void
        {
            add_options_page(
                __('Acme Bot Settings', 'acme-bot'),        // Page title
                __('Acme Bot', 'acme-bot'),                 // Menu title
                'manage_options',                            // Capability required
                'acme-bot-integration',                    // Menu slug
                [$this, 'create_admin_page']                // Function to display the page
            );
        }

        /**
         * Render the admin settings page.
         * Includes the template file for the settings page content.
         */
        public function create_admin_page(): void
        {
            // Path to the admin settings template file
            $template_path = plugin_dir_path(__FILE__) . 'admin/admin-settings-page.php';

            // Check if the template file exists and include it
            if (file_exists($template_path)) {
                include $template_path;
            } else {
                // Fallback message if the template is missing
                echo '<div class="wrap"><h1>' . esc_html__('Acme Bot Settings', 'acme-bot') . '</h1>';
                echo '<div class="notice notice-error"><p>' . esc_html__('Error: Settings page template not found at ', 'acme-bot') . esc_html($template_path) . '</p></div>';
                echo '</div>';
            }
        }

        /**
         * Display admin notices for settings errors.
         * Call this function in an admin_notices action hook.
         */
        public function display_settings_errors(): void
        {
            // Check if we have errors to display
            if (isset($_GET['acmebot_error']) && $_GET['acmebot_error'] === '1') {
                $errors = get_transient('acmebot_settings_errors');

                if ($errors && is_array($errors)) {
                    foreach ($errors as $error) {
                        echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($error) . '</p></div>';
                    }

                    // Clear the errors after displaying them
                    delete_transient('acmebot_settings_errors');
                }
            }

            // Display success message if we have one
            if (isset($_GET['acmebot_setup_success']) && $_GET['acmebot_setup_success'] === '1') {
                echo '<div class="notice notice-success is-dismissible"><p>' .
                    esc_html__('AcmeBot integration setup was successful!', 'acme-bot') .
                    '</p></div>';
            }
        }
    }

    // Instantiate the plugin class.
    new AcmeBot();
} // End if (!class_exists('AcmeBot'))
