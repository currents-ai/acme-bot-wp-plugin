<?php

/**
 * @link              https://acme.bot/
 * @since             1.0.0
 * @package           AcmeBot
 *
 * @wordpress-plugin
 * Plugin Name:     Acme Bot
 * Description:     Acme Bot - AI content agent for WordPress.
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
         * The option name used to store the ID of the user who initiated the integration.
         * Used as the default author and for verification tests.
         * @var string
         */
        const INTEGRATING_USER_ID_OPTION = 'acmebot_default_author_id';
        /**
         * Event name for integration creation confirmation.
         * This is used to confirm that the integration was successfully created.
         * @var bool
         */

        const IS_INTEGRATION_COMPLETED = 'integration_completed';

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
         * Default User ID to use if none provided or invalid in webhook/setup.
         * Usually ID 1 is the first admin user.
         * @var int
         */
        const DEFAULT_AUTHOR_ID = 1;

        /**
         * The URL for the Acme Bot API authorization.
         * @var string
         */
        const ACMEBOT_API_AUTHORIZE_URL = 'https://acme.bot/d/{cust_id}/connectors/create';

        /**
         * The host for the Acme Bot API.
         * @var string
         */
        const ACMEBOT_API_HOST = 'acme.bot';

        /**
         * Initialize the class and set up hooks.
         */
        public function __construct()
        {
            // Register REST API endpoints
            add_action('rest_api_init', [$this, 'register_rest_routes']); // Renamed for clarity

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
                // Display admin notices (e.g., errors, success messages)
                add_action('admin_notices', [$this, 'display_admin_notices']); // Consolidated notice display
                // Redirect to settings page after activation
                add_action('admin_init', [$this, 'handle_activation_redirect']); // Renamed for clarity

                // Cors preflight
                add_filter('rest_pre_serve_request', function ($served, $result) {
                    header('Access-Control-Allow-Origin: *');
                    header('Access-Control-Allow-Methods: POST, OPTIONS');
                    header('Access-Control-Allow-Headers: Content-Type, x-secret');
                    return $served;
                }, 10, 2);

                // Register activation hook to set up the plugin
                register_activation_hook(__FILE__, ['AcmeBot', 'activate']);
                // Register deactivation hook to clean up options
                register_deactivation_hook(__FILE__, ['AcmeBot', 'deactivate']); // Made static for consistency
            }
        }

        /**
         * Activation hook callback.
         * Sets a transient to trigger redirect on first admin load after activation.
         */
        public static function activate(): void
        {
            set_transient('acmebot_activation_redirect', true, 30);
            // We might initialize default options here if needed in the future
            if (!get_option(self::INTEGRATING_USER_ID_OPTION)) {
                update_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
            }
        }

        /**
         * Deactivation hook callback.
         * Cleans up the stored secret and integrating user ID options.
         */
        public static function deactivate(): void
        {
            delete_option(self::SECRET_OPTION);
            delete_option(self::INTEGRATING_USER_ID_OPTION);
            delete_transient('acmebot_settings_errors'); // Clean up transients too
            delete_transient('acmebot_activation_redirect');
        }


        /**
         * Handles the redirect to the settings page after plugin activation.
         * Runs on admin_init hook.
         */
        public function handle_activation_redirect(): void
        {
            if (get_transient('acmebot_activation_redirect')) {
                delete_transient('acmebot_activation_redirect');
                // Ensure this is not a bulk activation action
                if (!isset($_GET['activate-multi'])) {
                    wp_safe_redirect(admin_url('options-general.php?page=acme-bot-integration&acmebot_just_activated=1'));
                    exit;
                }
            }
        }

        /**
         * Register the REST API routes for the webhook and verification.
         */
        public function register_rest_routes(): void // Changed name
        {
            $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';

            // Webhook route for receiving events (like create_post)
            register_rest_route($namespace, '/posts', [
                'methods' => WP_REST_Server::CREATABLE, // POST
                'callback' => [$this, 'create_post'],
                'permission_callback' => '__return_true', // Security handled internally via secret
                'args' => [
                    'event' => [
                        'required' => true,
                        'type' => 'string',
                        'description' => __('The type of event being triggered.', 'acme-bot'),
                        'enum' => [self::EVENT_INTEGRATION_CREATED, self::EVENT_CREATE_POST], // Document possible events
                    ],
                    'payload' => [
                        'required' => true,
                        'type' => 'object',
                        'description' => __('The data associated with the event.', 'acme-bot'),
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

            // Verification route used after setup redirection
            register_rest_route($namespace, '/verify', [
                'methods' => WP_REST_Server::CREATABLE, // POST
                'callback' => [$this, 'handle_verification'],
                'permission_callback' => '__return_true', // Security handled internally via secret
                'args' => [
                    // Optional: could include user_id or other check from Acme side
                    'verification_token' => [
                        'required' => false, // Example: maybe Acme sends back a temporary token?
                        'type' => 'string',
                        'description' => __('Optional verification token.', 'acme-bot'),
                    ],
                ],
            ]);
        }

        /**
         * Verify the request secret against the stored secret.
         *
         * @param WP_REST_Request $request The request object.
         * @return bool|WP_REST_Response True if valid, WP_REST_Response on failure.
         */
        private function verify_secret(WP_REST_Request $request)
        {
            $received_secret = $request->get_header('x-secret');
            $stored_secret = get_option(self::SECRET_OPTION);

            if (empty($received_secret) || empty($stored_secret) || !hash_equals((string) $stored_secret, (string) $received_secret)) {
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => __('Unauthorized: Invalid or missing secret.', 'acme-bot'),
                ], 401);
            }
            return true;
        }

        /**
         * Handle incoming verification requests.
         * Attempts to create and delete a test post to confirm integration works.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function handle_verification(WP_REST_Request $request): WP_REST_Response
        {


            // // --- CORS Headers ---
            // header('Access-Control-Allow-Origin: https://acme.bot');
            // header('Access-Control-Allow-Methods: POST, OPTIONS');
            // header('Access-Control-Allow-Headers: Content-Type, x-secret');

            // // Handle preflight OPTIONS request
            // if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            //     // Return empty response for preflight
            //     return new WP_REST_Response(null, 204);
            // }


            // 1. Verify Secret
            $verification_result = $this->verify_secret($request);
            if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                return $verification_result;
            }

            try {
                // 2. Get Author ID (the user who set up the integration)
                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
                if (!get_user_by('ID', $author_id)) {
                    error_log('AcmeBot Verification Error: Stored integrating user ID (' . $author_id . ') is invalid.');
                    // Fallback or fail? Let's fail clearly.
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => __('Verification failed: Configured author user ID is invalid.', 'acme-bot'),
                    ], 500);
                }


                // 3. Prepare Test Post Data
                $test_post_data = [
                    'post_title'   => sprintf(__('AcmeBot Verification Post - %s', 'acme-bot'), time()),
                    'post_content' => __('This is a temporary post created automatically during AcmeBot integration verification. It should be deleted immediately.', 'acme-bot'),
                    'post_status'  => 'draft', // Use draft to avoid appearing on the live site
                    'post_author'  => $author_id,
                ];

                // 4. Attempt to Create Test Post
                $test_post_id = wp_insert_post($test_post_data, true); // Pass true to return WP_Error on failure

                if (is_wp_error($test_post_id)) {
                    error_log('AcmeBot Verification Error: Failed to create test post. WP_Error: ' . $test_post_id->get_error_message());
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => sprintf(__('Verification failed: Could not create test post. Error: %s', 'acme-bot'), $test_post_id->get_error_message()),
                    ], 500); // Internal server error likely due to permissions or DB issue
                }

                // 5. Attempt to Delete Test Post Immediately
                // Use force delete (true) to bypass trash
                $delete_result = wp_delete_post($test_post_id, true);

                if (!$delete_result) {
                    // Deletion failed, this is problematic but maybe not critical for *verification*?
                    // Log it, but maybe still return success as creation worked?
                    // Let's treat deletion failure as a verification failure for robustness.
                    error_log('AcmeBot Verification Error: Failed to delete test post ID: ' . $test_post_id);
                    // Attempt to trash it as a fallback? Or just report error.
                    wp_trash_post($test_post_id); // Try trashing at least
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => __('Verification partially failed: Could not automatically delete test post. Please check trash.', 'acme-bot'),
                    ], 500);
                }

                // Optionally, set a flag indicating successful verification if needed elsewhere
                update_option(self::IS_INTEGRATION_COMPLETED, true);

                return new WP_REST_Response([
                    'status' => 'SUCCESS',
                    'message' => __('AcmeBot integration verified successfully.', 'acme-bot'),
                ], 200);
            } catch (Exception $e) {
                error_log('AcmeBot Verification Exception: ' . $e->getMessage() . ' in ' . $e->getFile() . ' on line ' . $e->getLine());
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => sprintf(__('An unexpected error occurred during verification: %s', 'acme-bot'), $e->getMessage()),
                ], 500);
            }
        }


        /**
         * Handle incoming webhook requests.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function create_post(WP_REST_Request $request): WP_REST_Response
        {

            // 1. Verify Secret
            $verification_result = $this->verify_secret($request);
            $is_integration_completed = get_option(self::IS_INTEGRATION_COMPLETED, false);
            if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                // verify_secret already returns a WP_REST_Response with 401 status
                return $verification_result;
            }

            // Check if integration was created
            if (!$is_integration_completed) {
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => __('Integration not created or verified. Please check the setup.', 'acme-bot'),
                ], 403); // Forbidden
            }


            try {
                // 2. Process the Event
                $event = $request->get_param('event');
                $payload = $request->get_param('payload');

                // Basic validation
                if (empty($event)) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => __('Missing required parameter: event', 'acme-bot')
                    ], 400);
                }
                if (empty($payload)) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => __('Missing required parameter: payload', 'acme-bot')
                    ], 400);
                }


                switch ($event) {
                    case self::EVENT_INTEGRATION_CREATED:
                        return new WP_REST_Response([
                            'status' => 'SUCCESS', // Use consistent status
                            'message' => __('Webhook received integration confirmation.', 'acme-bot') // Clearer message
                        ], 200);

                    case self::EVENT_CREATE_POST:
                        return $this->handle_create_post($payload);

                    default:
                        // Event type not recognized
                        return new WP_REST_Response([
                            'status' => 'ERROR',
                            'message' => __('Event not recognized', 'acme-bot')
                        ], 400);
                }
            } catch (Exception $e) {
                // Log the full exception for debugging
                error_log('AcmeBot Webhook Error: ' . $e->getMessage() . ' in ' . $e->getFile() . ' on line ' . $e->getLine());

                // Return a controlled error response
                return new WP_REST_Response(
                    [
                        'status' => 'ERROR',
                        'message' => sprintf(__('Error processing webhook: %s', 'acme-bot'), $e->getMessage())
                    ],
                    500
                );
            }
        }

        /**
         * Handle the create_post event from the webhook.
         * 
         * @param array|object $payload The payload for the create_post event.
         * @return WP_REST_Response Response object.
         */
        private function handle_create_post($payload): WP_REST_Response
        {

            try {
                // Check if we're updating an existing post
                $is_update = isset($payload['post_id']) && is_numeric($payload['post_id']) && $payload['post_id'] > 0;
                $post_id = $is_update ? absint($payload['post_id']) : 0;
                $existing_post = null;

                // Verify post exists if we're updating
                if ($is_update) {
                    $existing_post = get_post($post_id);
                    if (!$existing_post) {
                        return new WP_REST_Response([
                            'status' => 'ERROR',
                            'message' => __('Invalid post_id: Post does not exist.', 'acme-bot'),
                        ], 404); // 404 Not Found is more appropriate
                    }
                }

                // Get title and content using null coalescing operator
                $title = $payload['title'] ?? null;
                $content = $payload['content'] ?? null;

                // Validate required fields for *new* posts
                if (!$is_update && (empty($title) || !isset($content))) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => __('Invalid payload: title is required and content must be present for new posts', 'acme-bot'),
                    ], 400);
                }

                // --- Post Author Handling ---
                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID); // Start with configured user or default

                // If updating, keep existing author unless explicitly overridden
                if ($is_update && $existing_post) {
                    $author_id = $existing_post->post_author;
                }

                // Allow overriding author via payload (check ID first, then name)
                $potential_author_id = null;
                if (isset($payload['user_id']) && is_numeric($payload['user_id']) && absint($payload['user_id']) > 0) {
                    $potential_author_id = absint($payload['user_id']);
                } elseif (isset($payload['user_name']) && is_string($payload['user_name']) && !empty(trim($payload['user_name']))) {
                    $username = sanitize_user(trim($payload['user_name']));
                    $user = get_user_by('login', $username); // Check login name first
                    if (!$user) { // Then check display name
                        $users = get_users(['search' => $username, 'search_columns' => ['display_name'], 'number' => 1]);
                        $user = !empty($users) ? $users[0] : null;
                    }
                    if ($user) {
                        $potential_author_id = $user->ID;
                    } else {
                        error_log('AcmeBot Webhook: Could not find user by name: ' . trim($payload['user_name']));
                    }
                }

                // If a valid user was found in payload, check if they can publish/edit, then use them.
                if ($potential_author_id && get_user_by('ID', $potential_author_id)) {
                    // Check capabilities (important!)
                    if (user_can($potential_author_id, 'publish_posts') && user_can($potential_author_id, 'edit_posts')) {
                        $author_id = $potential_author_id;
                    } else {
                        error_log('AcmeBot Webhook: User ID ' . $potential_author_id . ' provided in payload lacks publishing/editing capabilities. Using default author ID: ' . $author_id);
                    }
                } elseif ($potential_author_id) {
                    // ID or Name was provided but user doesn't exist
                    error_log('AcmeBot Webhook: User ID/Name provided in payload (' . ($payload['user_id'] ?? $payload['user_name']) . ') is invalid or user not found. Using default author ID: ' . $author_id);
                }


                // --- Category Handling ---
                $category_ids = [];
                if (isset($payload['categories']) && is_array($payload['categories'])) {
                    foreach ($payload['categories'] as $category_ref) {
                        $cat_id = 0;
                        if (is_int($category_ref) || (is_string($category_ref) && is_numeric($category_ref))) {
                            // Assume it's an ID
                            $term = term_exists(absint($category_ref), 'category');
                            if ($term !== 0 && $term !== null) { // term_exists returns array or null/0
                                $cat_id = (int)$term['term_id'];
                            }
                        } elseif (is_string($category_ref) && !empty(trim($category_ref))) {
                            // Assume it's a name
                            $category_name = sanitize_text_field(trim($category_ref));
                            $term = term_exists($category_name, 'category');
                            if ($term !== 0 && $term !== null) {
                                $cat_id = (int)$term['term_id'];
                            } else {
                                // Create category if it doesn't exist
                                $new_cat = wp_insert_term($category_name, 'category');
                                if (!is_wp_error($new_cat) && isset($new_cat['term_id'])) {
                                    $cat_id = (int)$new_cat['term_id'];
                                    error_log('AcmeBot Webhook: Created new category "' . $category_name . '" (ID: ' . $cat_id . ')');
                                } else {
                                    error_log('AcmeBot Webhook: Failed to create category "' . $category_name . '". Error: ' . (is_wp_error($new_cat) ? $new_cat->get_error_message() : 'Unknown error'));
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
                    'post_status' => $payload['post_status'] ?? ($is_update ? $existing_post->post_status : 'publish'), // Allow status override, default publish for new
                    'post_type'   => $payload['post_type'] ?? ($is_update ? $existing_post->post_type : 'post'), // Allow post type override
                    'post_author' => $author_id,
                    // Add more fields if needed (e.g., post_date, post_excerpt, meta_input)
                ];

                // Only include fields if they are explicitly provided in the payload or required
                if (isset($title)) {
                    $post_data['post_title'] = sanitize_text_field($title);
                }
                if (isset($content)) {
                    // Be careful with kses, ensure it allows necessary tags from AcmeBot
                    $post_data['post_content'] = wp_kses_post($content);
                }
                if (!empty($category_ids)) {
                    $post_data['post_category'] = $category_ids;
                }

                // For updates, set the ID
                if ($is_update) {
                    $post_data['ID'] = $post_id;
                    // If title/content not provided for update, they won't be changed.
                } else {
                    // Ensure essential fields have defaults if not provided for new posts
                    if (!isset($post_data['post_title'])) $post_data['post_title'] = __('Untitled Post', 'acme-bot'); // Default title
                    if (!isset($post_data['post_content'])) $post_data['post_content'] = ''; // Default content
                }

                // --- Insert or Update Post ---
                $result_post_id = wp_insert_post($post_data, true); // Pass true for WP_Error return

                // Check for errors
                if (is_wp_error($result_post_id)) {
                    $action = $is_update ? 'update' : 'create';
                    error_log("AcmeBot Error: Failed to {$action} post via webhook. WP_Error: " . $result_post_id->get_error_message());
                    return new WP_REST_Response(
                        [
                            'status' => 'ERROR',
                            'message' => sprintf(__("Failed to {$action} post: %s", 'acme-bot'), $result_post_id->get_error_message()),
                        ],
                        500 // Internal Server Error
                    );
                }

                // --- Success ---
                $post_url = get_permalink($result_post_id);
                $action = $is_update ? 'updated' : 'created';
                $status_code = $is_update ? 200 : 201; // 201 Created for new posts

                return new WP_REST_Response([
                    'status' => 'SUCCESS',
                    'message' => sprintf(__('Post %s successfully', 'acme-bot'), $action),
                    'data' => [ // Nest details under 'data'
                        'post_id' => $result_post_id,
                        'url' => $post_url,
                    ]
                ], $status_code);
            } catch (Exception $e) {
                error_log('AcmeBot Error in post handler: ' . $e->getMessage() . ' in ' . $e->getFile() . ' on line ' . $e->getLine());
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => sprintf(__('Error handling post creation/update: %s', 'acme-bot'), $e->getMessage()),
                ], 500);
            }
        }


        /**
         * Handles the form submission from the settings page.
         * Generates a strong secret, saves it, stores the integrating user ID,
         * and redirects to the external service for authorization.
         */
        public function handle_form_submission(): void
        {
            $errors = [];

            // 1. Verify Nonce
            if (!isset($_POST['acmebot_settings_nonce']) || !wp_verify_nonce(sanitize_key($_POST['acmebot_settings_nonce']), 'acmebot_settings_action')) {
                $errors[] = __('Security check failed. Please try submitting the form again.', 'acme-bot');
            }

            // 2. Check Capabilities
            if (!current_user_can('manage_options')) {
                $errors[] = __('You do not have permission to manage options.', 'acme-bot');
                // manage_options usually implies edit/publish, but let's be explicit for clarity
            }
            if (!current_user_can('publish_posts') || !current_user_can('edit_posts')) {
                $errors[] = __('You need permissions to publish and edit posts to set up this integration.', 'acme-bot');
            }


            // 3. Get Current User ID
            $integrating_user_id = get_current_user_id();
            if ($integrating_user_id <= 0) { // Check if ID is valid
                $errors[] = __('Could not identify the current logged-in user.', 'acme-bot');
            }

            // Handle errors
            if (!empty($errors)) {
                set_transient('acmebot_settings_errors', $errors, 300); // Store for 5 minutes
                wp_safe_redirect(add_query_arg('acmebot_error', '1', admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }

            // Proceed if no errors
            try {
                // Store the integrating user's ID as the default author
                if (!update_option(self::INTEGRATING_USER_ID_OPTION, $integrating_user_id)) {
                    // Log a warning if update failed, but maybe proceed? The default might exist.
                    error_log('AcmeBot Setup Warning: Failed to update the integrating user ID option (' . self::INTEGRATING_USER_ID_OPTION . ') to ' . $integrating_user_id . '. Using previous or default value.');
                }


                // Generate and Store Strong Secret
                $secret = wp_generate_password(128, false);
                if (!update_option(self::SECRET_OPTION, $secret)) {
                    // This is critical, throw an error if secret saving fails
                    throw new Exception(__('Failed to save the integration secret key to the database.', 'acme-bot'));
                }

                $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';
                $webhook_url = rest_url($namespace);
                $verify_url = rest_url($namespace . '/verify');
                $post_url = rest_url($namespace . '/posts');
                $site_url = site_url();
                $site_name = get_bloginfo('name');
                $redirect_url = add_query_arg(
                    urlencode_deep([
                        'webhook_url' => $webhook_url,
                        // 'verify_url' => $verify_url,
                        // 'post_url' => $post_url,
                        'secret' => $secret,
                        'user_id' => $integrating_user_id,
                        'site_url' => $site_url,
                        'site_name' => $site_name,
                        // 'return_url_success' => admin_url('options-general.php?page=acme-bot-integration&acmebot_setup_success=1'), // URL to redirect back on success
                        // 'return_url_fail' => admin_url('options-general.php?page=acme-bot-integration&acmebot_setup_fail=1'),   // URL to redirect back on failure
                    ]),
                    self::ACMEBOT_API_AUTHORIZE_URL
                );

                // Redirect User
                wp_safe_redirect($redirect_url);
                exit;
            } catch (Exception $e) {
                error_log('Acme Bot Setup Error: ' . $e->getMessage());
                set_transient('acmebot_settings_errors', [$e->getMessage()], 300);
                wp_safe_redirect(add_query_arg('acmebot_error', '1', admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }
        }

        /**
         * Add settings action link to the plugins page.
         */
        public function add_settings_link(array $links): array
        {
            $settings_link = sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('options-general.php?page=acme-bot-integration')),
                esc_html__('Settings', 'acme-bot')
            );
            array_unshift($links, $settings_link);
            return $links;
        }


        /**
         * Add the Acme Bot API host to the list of allowed redirect hosts.
         */
        public function add_acmebot_allowed_host(array $hosts): array
        {
            if (!in_array(self::ACMEBOT_API_HOST, $hosts)) {
                $hosts[] = self::ACMEBOT_API_HOST;
            }
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
                [$this, 'render_admin_page']                // Function to display the page (renamed)
            );
        }

        /**
         * Render the admin settings page content by including the template file.
         */
        public function render_admin_page(): void // Renamed
        {
            $template_path = plugin_dir_path(__FILE__) . 'admin/admin-settings-page.php';

            if (file_exists($template_path)) {
                include $template_path;
            } else {
                echo '<div class="wrap"><h1>' . esc_html__('Acme Bot Settings', 'acme-bot') . '</h1>';
                echo '<div class="notice notice-error"><p>' . sprintf(
                    esc_html__('Error: Settings page template not found at %s', 'acme-bot'),
                    '<code>' . esc_html($template_path) . '</code>'
                ) . '</p></div>';
                echo '</div>';
            }
        }

        /**
         * Display admin notices for settings errors, success messages, etc.
         * Consolidated from display_settings_errors.
         */
        public function display_admin_notices(): void
        {
            // Check for errors stored in transient
            if (isset($_GET['acmebot_error']) && $_GET['acmebot_error'] === '1') {
                $errors = get_transient('acmebot_settings_errors');
                if ($errors && is_array($errors)) {
                    foreach ($errors as $error) {
                        echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($error) . '</p></div>';
                    }
                    delete_transient('acmebot_settings_errors'); // Clear after displaying
                }
            }

            // Check for success message from setup redirect
            if (isset($_GET['acmebot_setup_success']) && $_GET['acmebot_setup_success'] === '1') {
                echo '<div class="notice notice-success is-dismissible"><p>' .
                    esc_html__('AcmeBot integration setup and verification successful!', 'acme-bot') .
                    '</p></div>';
                // Optionally, remove the query arg visually using JS or a redirect without it
            }

            // Check for failure message from setup redirect
            if (isset($_GET['acmebot_setup_fail']) && $_GET['acmebot_setup_fail'] === '1') {
                echo '<div class="notice notice-warning is-dismissible"><p>' .
                    esc_html__('AcmeBot integration setup failed or verification could not be completed. Please check the connection or try again.', 'acme-bot') .
                    '</p></div>';
                // Optionally, remove the query arg
            }

            // Check for message after activation redirect
            if (isset($_GET['acmebot_just_activated']) && $_GET['acmebot_just_activated'] === '1') {
                // Don't show an error if secret isn't set yet on first activation visit
                if (!get_option(self::SECRET_OPTION)) {
                    echo '<div class="notice notice-info is-dismissible"><p>' .
                        esc_html__('Welcome to AcmeBot! Please click the "Connect to AcmeBot" button below to complete the setup.', 'acme-bot') .
                        '</p></div>';
                }
                // Optionally, remove the query arg
            }

            // General check: Remind user to connect if secret is missing (and not just activated)
            $current_screen = get_current_screen();
            if (
                $current_screen && $current_screen->id === 'settings_page_acme-bot-integration' &&
                !get_option(self::SECRET_OPTION) &&
                !isset($_GET['acmebot_just_activated']) &&
                !isset($_GET['acmebot_setup_fail']) // Don't show if setup just failed
            ) {
                echo '<div class="notice notice-warning is-dismissible"><p>' .
                    esc_html__('AcmeBot is not yet connected. Click the "Connect to AcmeBot" button to start the integration.', 'acme-bot') .
                    '</p></div>';
            }
        } // end display_admin_notices

    } // End class AcmeBot

    // Instantiate the plugin class.
    new AcmeBot();
} // End if (!class_exists('AcmeBot'))