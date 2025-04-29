<?php
/**
 * @link              https://example.com/acme-bot
 * @since             1.0.1
 * @package           AcmeBot
 *
 * @wordpress-plugin
 * Plugin Name:     Acme Bot
 * Description:     Acme Bot - AI assistant for WordPress.
 * Version:         1.0.3  <!-- Version bumped -->
 * Author:          Acme Bot Team
 * Author URI:      https://example.com/acme-bot
 * License:         GPL-2.0 or later
 * License URI:     http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:     acme-bot
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
        const ACMEBOT_API_AUTHORIZE_URL = 'https://acme.bot/api_acme/wp-plugin/authorize'; // <<--- CHANGE THIS to the actual Acme Bot API endpoint;

        
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

                //Register activation hook to set up the plugin
                register_activation_hook(__FILE__, ['AcmeBot', 'activate']);

                // Register deactivation hook to clean up options
                register_deactivation_hook(__FILE__, [$this, 'deactivate']);
            }
        }

        // Add this inside your main plugin class
        public static function activate() {
            // Set a transient to trigger the redirect after activation
            set_transient('acmebot_activation_redirect', true, 30);
        }

        public function admin_init() {
            // Check if we should redirect
            if (get_transient('acmebot_activation_redirect')) {
                // Delete the transient so it only happens once
                delete_transient('acmebot_activation_redirect');
                
                // Make sure it's the proper admin page
                if (!isset($_GET['activate-multi'])) {
                    // Redirect to the settings page
                    wp_safe_redirect(admin_url('options-general.php?page=acme-bot-setting-admin'));
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

            switch ($event) {
                case self::EVENT_INTEGRATION_CREATED:
                    // Simple success response for integration confirmation
                    return new WP_REST_Response(__('Integration successful', 'acme-bot'), 200);
                    break; // Added for clarity

                case self::EVENT_CREATE_POST:
                    // Validate payload structure
                    if (!is_array($payload)) {
                         // Use is_object for REST requests often, but array access is used below.
                         // get_param typically decodes JSON objects into assoc arrays by default.
                         // Check if it's array-like or log actual type if needed.
                        error_log('Acme Bot Webhook: Received non-array payload for create_post. Type: ' . gettype($payload));
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
                    if (isset($payload['user_id']) && is_numeric($payload['user_id'])) {
                        $potential_author_id = absint($payload['user_id']); // Ensure positive integer
                        if ($potential_author_id > 0 && get_user_by('ID', $potential_author_id)) {
                             // Check if user exists
                             // Optional: Check if user can publish posts: if (user_can($potential_author_id, 'publish_posts'))
                             $author_id = $potential_author_id;
                        } else {
                            // Log if provided user ID is invalid but was provided
                            error_log('Acme Bot Webhook: Invalid or non-existent user_id provided: ' . $payload['user_id']);
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
                                }
                                // Optional: Create category if it doesn't exist
                                // else { $new_cat = wp_create_category($category_name); if(!is_wp_error($new_cat)) $cat_id = $new_cat; }
                            }

                            if ($cat_id > 0 && !in_array($cat_id, $category_ids)) {
                                $category_ids[] = $cat_id;
                            }
                        }
                    }

                    // --- Sanitize and Prepare Post Data ---
                    $post_data = array(
                        'post_title'   => sanitize_text_field($title),
                        'post_content' => wp_kses_post($content), // Allows safe HTML
                        'post_status'  => 'publish',             // Or 'draft' etc.
                        'post_author'  => $author_id,
                    );

                    // Add categories if any were validated
                    if (!empty($category_ids)) {
                        $post_data['post_category'] = $category_ids;
                    }

                    // --- Insert Post ---
                    $post_id = wp_insert_post($post_data, true); // Pass true to return WP_Error on failure

                    // Check for errors during post creation
                    if (is_wp_error($post_id)) {
                        // Log the error for administrators
                        error_log('Acme Bot Error: Failed to create post via webhook. WP_Error: ' . $post_id->get_error_message());
                        // Return a server error response
                        return new WP_REST_Response(sprintf(__('Failed to create post: %s', 'acme-bot'), $post_id->get_error_message()), 500);
                    }

                    // Post created successfully
                    $post_url = get_permalink($post_id);
                    return new WP_REST_Response(array(
                        'message' => __('Post created successfully', 'acme-bot'),
                        'post_id' => $post_id,
                        'url' => $post_url
                    ), 200);
                    break; // Added for clarity

                default:
                    // Event type not recognized
                    return new WP_REST_Response(__('Event not recognized', 'acme-bot'), 400);
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

            // 1. Verify Nonce for Security
            if (!isset($_POST['acmebot_settings_nonce']) || !wp_verify_nonce(sanitize_key($_POST['acmebot_settings_nonce']), 'acmebot_settings_action')) {
                wp_die(__('Invalid nonce specified', 'acme-bot'), __('Error', 'acme-bot'), [
                    'response' 	=> 403,
                    'back_link' => true, // Provides a back link
                ]);
            }

            // 2. Check User Capabilities
            if (!current_user_can('manage_options')) {
                 wp_die(__('You do not have sufficient permissions to perform this action.', 'acme-bot'), __('Error', 'acme-bot'), [
                    'response' 	=> 403,
                    'back_link' => true,
                ]);
            }

            // 3. Get Current User ID (The admin setting up the integration)
             $integrating_user_id = get_current_user_id();
             if($integrating_user_id === 0) {
                 // This shouldn't happen in admin context, but good to check.
                 wp_die(__('Could not determine your User ID. Please ensure you are logged in.', 'acme-bot'), __('Error', 'acme-bot'), [
                    'response' 	=> 500,
                    'back_link' => true,
                 ]);
             }
             // Optional: Store this user ID if needed locally for fallback author assignment later
             // update_option('acmebot_integrating_user_id', $integrating_user_id);


            // 4. Generate and Store Strong Secret
            $secret = wp_generate_password(64, true);
            update_option(self::SECRET_OPTION, $secret);

            // 5. Prepare Redirect URL
            $webhook_url = esc_url_raw(rest_url('acmebot/v' . self::REST_VERSION . '/webhook'));
            $redirect_url = add_query_arg(
                array(
                    'webhook_url' => urlencode($webhook_url),      // URL encode query parameter values
                    'secret'      => urlencode($secret),           // URL encode query parameter values
                    'user_id'     => urlencode($integrating_user_id) // URL encode the integrating user ID
                ),
                self::ACMEBOT_API_AUTHORIZE_URL
            );

            // 6. Redirect User
            wp_safe_redirect($redirect_url); // Use wp_safe_redirect for external URLs when possible
            exit; // IMPORTANT: Always exit after wp_redirect to prevent further execution
        }

        /**
         * Add settings action link to the plugins page.
         *
         * @param array $links An array of plugin action links.
         * @return array An array of plugin action links.
         */
        public function add_settings_link(array $links): array
        {
            $settings_link = '<a href="' . esc_url(admin_url('options-general.php?page=acme-bot-setting-admin')) . '">' . esc_html__('Settings', 'acme-bot') . '</a>';
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
                'acme-bot-setting-admin',                    // Menu slug
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
                echo '<div class="notice notice-error"><p>' . esc_html__('Error: Settings page template not found at ', 'acme-bot') . esc_html($template_path) .'</p></div>';
                echo '</div>';
            }
        }
    }

    // Instantiate the plugin class.
    new AcmeBot();
} // End if (!class_exists('AcmeBot'))
