<?php

/**
 * @link              https://acme.bot/
 * @since             1.0.0
 * @package           AcmeBot
 *
 * @wordpress-plugin
 * Plugin Name:     ACME.BOT - AI SEO Writer & Content Generator
 * Description:     Run your WordPress blog on auto-pilot with ACME.BOT - the fully automated AI SEO writer that creates deep-researched, publish-ready content with AI diagrams.
 * Version:         1.0.0 
 * Author:          ACME.BOT
 * Author URI:      https://acme.bot/
 * License:         GPL-2.0 or later
 * License URI:     http://www.gnu.org/licenses/gpl-2.0.txt
 * Requires at least: 5.0
 * Requires PHP: 7.4
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
        /** REST API version */
        const REST_VERSION = 1;

        /** Option for secret key storage */
        const SECRET_OPTION = 'acmebot_secret';

        /** Option for the user ID who initiated integration (default author) */
        const INTEGRATING_USER_ID_OPTION = 'acmebot_default_author_id';

        /** Flag for completed integration */
        const IS_INTEGRATION_COMPLETED = 'acmebot_integration_completed';

        /** Integration created event */
        const EVENT_INTEGRATION_CREATED = 'integration_created';

        /** Post creation event */
        const EVENT_CREATE_POST = 'create_post';

        /** Default admin user ID */
        const DEFAULT_AUTHOR_ID = 1;

        /** Base URL for API endpoints */
        const BASE_URL = 'http://localhost:8001'; // 'https://acme.bot';

        /** API authorization URL */
        const ACMEBOT_API_AUTHORIZE_URL = self::BASE_URL . '/d/{cust_id}/connectors/create';

        /** API host domain */
        const ACMEBOT_API_HOST = 'acme.bot';

        /**
         * Initialize the class and set up hooks.
         */
        public function __construct()
        {
            // Register REST API endpoints
            add_action('rest_api_init', [$this, 'register_rest_routes']);

            // Admin specific hooks
            if (is_admin()) {
                add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
                add_filter('allowed_redirect_hosts', [$this, 'add_acmebot_allowed_host']);
                add_action('admin_menu', [$this, 'add_plugin_page']);
                add_action('admin_post_acmebot_handle_form', [$this, 'handle_form_submission']);
                add_action('admin_notices', [$this, 'display_admin_notices']);
                add_action('admin_init', [$this, 'handle_activation_redirect']);

                // Cors preflight
                add_filter('rest_pre_serve_request', function ($served, $result) {
                    header('Access-Control-Allow-Origin: *');
                    header('Access-Control-Allow-Methods: POST, OPTIONS');
                    header('Access-Control-Allow-Headers: Content-Type, x-secret');
                    return $served;
                }, 10, 2);

                register_activation_hook(__FILE__, ['AcmeBot', 'activate']);
                register_deactivation_hook(__FILE__, ['AcmeBot', 'deactivate']);
            }
        }

        /**
         * Activation hook callback.
         */
        public static function activate(): void
        {
            set_transient('acmebot_activation_redirect', true, 30);

            if (!get_option(self::INTEGRATING_USER_ID_OPTION)) {
                update_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
            }
        }

        /**
         * Deactivation hook callback.
         */
        public static function deactivate(): void
        {
            delete_option(self::SECRET_OPTION);
            delete_option(self::INTEGRATING_USER_ID_OPTION);
            delete_option(self::IS_INTEGRATION_COMPLETED);
            delete_transient('acmebot_settings_errors');
            delete_transient('acmebot_activation_redirect');
        }

        /**
         * Handles redirect to settings page after plugin activation.
         */
        public function handle_activation_redirect(): void
        {
            if (get_transient('acmebot_activation_redirect')) {
                delete_transient('acmebot_activation_redirect');

                $activate_multi = sanitize_key(filter_input(INPUT_GET, 'activate-multi', FILTER_SANITIZE_FULL_SPECIAL_CHARS));

                if (empty($activate_multi)) {
                    wp_safe_redirect(add_query_arg(
                        [
                            'page' => 'acme-bot-integration',
                            'acmebot_just_activated' => '1',
                            'acmebot_nonce' => wp_create_nonce('acmebot_admin_notices')
                        ],
                        admin_url('options-general.php')
                    ));
                    exit;
                }
            }
        }

        public static function get_asset_url($relative_path)
        {
            return plugins_url('assets/' . $relative_path, __FILE__);
        }

        /**
         * Register REST API routes.
         */
        public function register_rest_routes(): void
        {
            $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';

            // Webhook route for events
            register_rest_route($namespace, '/posts', [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'create_post'],
                'permission_callback' => '__return_true',
                'args' => [
                    'payload' => [
                        'required' => true,
                        'type' => 'object',
                        'description' => 'The data associated with the post.',
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

            // Verification route
            register_rest_route($namespace, '/verify', [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'handle_verification'],
                'permission_callback' => '__return_true',
                'args' => [
                    'verification_token' => [
                        'required' => false,
                        'type' => 'string',
                        'description' => 'Optional verification token.',
                    ],
                ],
            ]);
        }

        /**
         * Verify the request secret.
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
                    'message' => 'Unauthorized: Invalid or missing secret.',
                ], 401);
            }
            return true;
        }

        /**
         * Handle verification requests.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function handle_verification(WP_REST_Request $request): WP_REST_Response
        {
            // Verify Secret
            $verification_result = $this->verify_secret($request);
            if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                return $verification_result;
            }

            try {
                // Get Author ID
                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);

                if (!get_user_by('ID', $author_id)) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => 'Verification failed: Configured author user ID is invalid.',
                    ], 403);
                }

                // Prepare Test Post Data
                $test_post_data = [
                    'post_title'   => sprintf('AcmeBot Verification Post - %s', time()),
                    'post_content' => 'This is a temporary post created automatically during AcmeBot integration verification. It should be deleted immediately.',
                    'post_status'  => 'draft',
                    'post_author'  => $author_id,
                ];

                // Create Test Post
                $test_post_id = wp_insert_post($test_post_data, true);

                if (is_wp_error($test_post_id)) {
                    $error_code = $test_post_id->get_error_code();
                    $status_code = 500;

                    if (in_array($error_code, ['insufficient_permissions', 'invalid_author'])) {
                        $status_code = 403;
                    }

                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => sprintf('Verification failed: Could not create test post. Error: %s', $test_post_id->get_error_message()),
                    ], $status_code);
                }

                $delete_result = wp_delete_post($test_post_id, true);

                if (!$delete_result) {
                    wp_trash_post($test_post_id);
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => 'Verification partially failed: Could not automatically delete test post. Please check trash.',
                    ], 207);
                }

                update_option(self::IS_INTEGRATION_COMPLETED, true);

                return new WP_REST_Response([
                    'status' => 'SUCCESS',
                    'message' => 'AcmeBot integration verified successfully.',
                ], 200);
            } catch (Exception $e) {
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => sprintf('An unexpected error occurred during verification: %s', $e->getMessage()),
                ], 500);
            }
        }

        /**
         * Handle webhook requests.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function create_post(WP_REST_Request $request): WP_REST_Response
        {
            // Verify Secret
            $verification_result = $this->verify_secret($request);
            $is_integration_completed = get_option(self::IS_INTEGRATION_COMPLETED, false);
            if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                return $verification_result;
            }

            if (!$is_integration_completed) {
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => 'Integration not created or verified. Please check the setup.',
                ], 403);
            }

            try {
                $payload = $request->get_param('payload');
                if (empty($payload)) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => 'Missing required parameter: payload'
                    ], 400);
                }

                return $this->handle_create_post($payload);
            } catch (Exception $e) {

                return new WP_REST_Response(
                    [
                        'status' => 'ERROR',
                        'message' => sprintf('Error processing webhook: %s', $e->getMessage())
                    ],
                    500
                );
            }
        }

        /**
         * Handle the create_post event.
         * 
         * @param array|object $payload The payload for the create_post event.
         * @return WP_REST_Response Response object.
         */
        private function handle_create_post($payload): WP_REST_Response
        {
            try {
                // Check if updating existing post
                $is_update = isset($payload['post_id']) && is_numeric($payload['post_id']) && $payload['post_id'] > 0;
                $post_id = $is_update ? absint($payload['post_id']) : 0;
                $existing_post = null;

                // Verify post exists if updating
                if ($is_update) {
                    $existing_post = get_post($post_id);
                    if (!$existing_post) {
                        return new WP_REST_Response([
                            'status' => 'ERROR',
                            'message' => 'Invalid post_id: Post does not exist.',
                        ], 404);
                    }
                }

                // Get title and content
                $title = $payload['title'] ?? null;
                $content = $payload['content'] ?? null;

                // Validate required fields for new posts
                if (!$is_update && (empty($title) || !isset($content))) {
                    return new WP_REST_Response([
                        'status' => 'ERROR',
                        'message' => 'Invalid payload: title is required and content must be present for new posts',
                    ], 400);
                }

                // Post Author Handling
                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);

                // If updating, keep existing author unless overridden
                if ($is_update && $existing_post) {
                    $author_id = $existing_post->post_author;
                }

                // Allow overriding author via payload
                $potential_author_id = null;
                if (isset($payload['user_id']) && is_numeric($payload['user_id']) && absint($payload['user_id']) > 0) {
                    $potential_author_id = absint($payload['user_id']);
                } elseif (isset($payload['user_name']) && is_string($payload['user_name']) && !empty(trim($payload['user_name']))) {
                    $username = sanitize_user(trim($payload['user_name']));
                    $user = get_user_by('login', $username);
                    if (!$user) {
                        $users = get_users(['search' => $username, 'search_columns' => ['display_name'], 'number' => 1]);
                        $user = !empty($users) ? $users[0] : null;
                    }
                    if ($user) {
                        $potential_author_id = $user->ID;
                    }
                }

                // Check if potential author has required capabilities
                if ($potential_author_id && get_user_by('ID', $potential_author_id)) {
                    if (user_can($potential_author_id, 'publish_posts') && user_can($potential_author_id, 'edit_posts')) {
                        $author_id = $potential_author_id;
                    }
                }

                // Category Handling
                $category_ids = [];
                if (isset($payload['categories']) && is_array($payload['categories'])) {
                    foreach ($payload['categories'] as $category_ref) {
                        $cat_id = 0;
                        if (is_int($category_ref) || (is_string($category_ref) && is_numeric($category_ref))) {
                            // Assume it's an ID
                            $term = term_exists(absint($category_ref), 'category');
                            if ($term !== 0 && $term !== null) {
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
                                }
                            }
                        }

                        if ($cat_id > 0 && !in_array($cat_id, $category_ids)) {
                            $category_ids[] = $cat_id;
                        }
                    }
                }

                // Sanitize and Prepare Post Data
                $post_data = [
                    'post_status' => $payload['post_status'] ?? ($is_update ? $existing_post->post_status : 'publish'),
                    'post_type'   => $payload['post_type'] ?? ($is_update ? $existing_post->post_type : 'post'),
                    'post_author' => $author_id,
                ];

                // Include fields if provided or required
                if (isset($title)) {
                    $post_data['post_title'] = sanitize_text_field($title);
                }
                if (isset($content)) {
                    $post_data['post_content'] = wp_kses_post($content);
                }
                if (!empty($category_ids)) {
                    $post_data['post_category'] = $category_ids;
                }

                // For updates, set the ID
                if ($is_update) {
                    $post_data['ID'] = $post_id;
                } else {
                    if (!isset($post_data['post_title'])) $post_data['post_title'] = 'Untitled Post';
                    if (!isset($post_data['post_content'])) $post_data['post_content'] = '';
                }

                // Insert or Update Post
                $result_post_id = wp_insert_post($post_data, true);

                // Check for errors
                if (is_wp_error($result_post_id)) {
                    $action = $is_update ? 'update' : 'create';
                    return new WP_REST_Response(
                        [
                            'status' => 'ERROR',
                            'message' => sprintf("Failed to {$action} post: %s", $result_post_id->get_error_message()),
                        ],
                        500
                    );
                }

                // Success
                $post_url = get_permalink($result_post_id);
                $action = $is_update ? 'updated' : 'created';
                $status_code = $is_update ? 200 : 201;

                return new WP_REST_Response([
                    'status' => 'SUCCESS',
                    'message' => sprintf('Post %s successfully', $action),
                    'data' => [
                        'post_id' => $result_post_id,
                        'url' => $post_url,
                    ]
                ], $status_code);
            } catch (Exception $e) {
                return new WP_REST_Response([
                    'status' => 'ERROR',
                    'message' => sprintf('Error handling post creation/update: %s', $e->getMessage()),
                ], 500);
            }
        }

        /**
         * Handles form submission from the settings page.
         */
        public function handle_form_submission(): void
        {
            $errors = [];

            // Verify Nonce
            if (!isset($_POST['acmebot_settings_nonce']) || !wp_verify_nonce(sanitize_key($_POST['acmebot_settings_nonce']), 'acmebot_settings_action')) {
                $errors[] = 'Security check failed. Please try submitting the form again.';
            }

            // Check Capabilities
            if (!current_user_can('manage_options')) {
                $errors[] = 'You do not have permission to manage options.';
            }
            if (!current_user_can('publish_posts') || !current_user_can('edit_posts')) {
                $errors[] = 'You need permissions to publish and edit posts to set up this integration.';
            }

            // Get Current User ID
            $integrating_user_id = get_current_user_id();
            if ($integrating_user_id <= 0) {
                $errors[] = 'Could not identify the current logged-in user.';
            }

            // Handle errors
            if (!empty($errors)) {
                set_transient('acmebot_settings_errors', $errors, 300);
                wp_safe_redirect(add_query_arg([
                    'acmebot_error' => '1',
                    'acmebot_nonce' => wp_create_nonce('acmebot_admin_notices')
                ],  admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }

            // Proceed if no errors
            try {
                // Store the integrating user's ID as default author
                update_option(self::INTEGRATING_USER_ID_OPTION, $integrating_user_id);

                // Generate and Store Secret
                $secret = wp_generate_password(128, false);
                update_option(self::SECRET_OPTION, $secret);

                $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';
                $webhook_url = rest_url($namespace);
                $verify_url = rest_url($namespace . '/verify');
                $post_url = rest_url($namespace . '/posts');
                $site_url = site_url();
                $current_user = wp_get_current_user();
                $username = $current_user->user_login;

                $acme_auth_url = add_query_arg(
                    urlencode_deep([
                        'form_data.webhook_url' => $webhook_url,
                        'form_data.verify_url' => $verify_url,
                        'form_data.post_url' => $post_url,
                        'form_data.secret' => $secret,
                        'form_data.username' => $username,
                        'form_data.site' => $site_url,
                        'form_data.connector_flow_type' => 'CONNECTOR_WORDPRESS_PLUGIN',
                        'update_form' => 'false',
                        'flow_type' => 'CONNECTOR',
                        // 'form_data.return_url_fail' => admin_url('options-general.php?page=acme-bot-integration&acmebot_setup_fail=1'),
                    ]),
                    urlencode(self::ACMEBOT_API_AUTHORIZE_URL)
                );

                $redirect_url = add_query_arg('redirect_path', urlencode($acme_auth_url), self::BASE_URL . '/login');
                wp_safe_redirect($redirect_url);
                exit;
            } catch (Exception $e) {
                set_transient('acmebot_settings_errors', [$e->getMessage()], 300);
                wp_safe_redirect(add_query_arg('acmebot_error', '1', admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }
        }

        /**
         * Add settings link to plugins page.
         */
        public function add_settings_link(array $links): array
        {
            $settings_link = sprintf(
                '<a href="%s">%s</a>',
                esc_url(admin_url('options-general.php?page=acme-bot-integration')),
                'Settings'
            );
            array_unshift($links, $settings_link);
            return $links;
        }

        /**
         * Add the Acme Bot API host to allowed redirect hosts.
         */
        public function add_acmebot_allowed_host(array $hosts): array
        {
            if (!in_array(self::ACMEBOT_API_HOST, $hosts)) {
                $hosts[] = self::ACMEBOT_API_HOST;
            }
            return $hosts;
        }

        /**
         * Add options page.
         */
        public function add_plugin_page(): void
        {
            add_options_page(
                'Acme Bot Settings',
                'Acme Bot',
                'manage_options',
                'acme-bot-integration',
                [$this, 'render_admin_page']
            );
        }

        /**
         * Render the admin settings page.
         */
        public function render_admin_page(): void
        {
            $template_path = plugin_dir_path(__FILE__) . 'admin/admin-settings-page.php';

            if (file_exists($template_path)) {
                include $template_path;
            } else {
                echo '<div class="wrap"><h1>' . 'Acme Bot Settings' . '</h1>';
                echo '<div class="notice notice-error"><p>' . sprintf(
                    esc_html('Error: Settings page template not found at %s'),
                    '<code>' . esc_html($template_path) . '</code>'
                ) . '</p></div>';
                echo '</div>';
            }
        }

        /**
         * Display admin notices.
         */
        public function display_admin_notices(): void
        {

            $nonce_action = 'acmebot_admin_notices';

            // Check if our nonce is set in the URL
            $has_valid_nonce = isset($_GET['acmebot_nonce']) &&
                wp_verify_nonce(sanitize_key($_GET['acmebot_nonce']), $nonce_action);

            // Check for errors stored in transient
            if (isset($_GET['acmebot_error']) && $_GET['acmebot_error'] === '1' && $has_valid_nonce) {
                $errors = get_transient('acmebot_settings_errors');
                if ($errors && is_array($errors)) {
                    foreach ($errors as $error) {
                        echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($error) . '</p></div>';
                    }
                    delete_transient('acmebot_settings_errors');
                }
            }


            // Check for message after activation redirect
            if (isset($_GET['acmebot_just_activated']) && $_GET['acmebot_just_activated'] === '1' && $has_valid_nonce) {
                if (!get_option(self::SECRET_OPTION)) {
                    echo '<div class="notice notice-info is-dismissible"><p>' .
                        'Welcome to AcmeBot! Please click the "Connect to AcmeBot" button below to complete the setup.' .
                        '</p></div>';
                }
            }
        }
    }

    // Instantiate the plugin class.
    new AcmeBot();
}
