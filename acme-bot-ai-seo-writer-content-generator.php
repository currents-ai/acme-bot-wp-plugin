<?php

/**
 * @link              https://acme.bot/
 * @since             1.0.0
 * @package           AcmeBot
 *
 * @wordpress-plugin
 * Plugin Name:     ACME.BOT - AI SEO Writer & Content Generator
 * Description:     Run your WordPress blog on auto-pilot with ACME.BOT - the fully automated AI SEO writer that creates deep-researched, publish-ready content with AI diagrams.
 * Version:         1.0.2
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
        const BASE_URL = 'https://acme.bot';

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
            // Initialize SEO hooks
            add_action('init', [$this, 'init_seo_hooks']);

            // Admin specific hooks
            if (is_admin()) {
                add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);
                add_filter('allowed_redirect_hosts', [$this, 'add_acmebot_allowed_host']);
                add_action('admin_menu', [$this, 'add_plugin_page']);
                add_action('admin_post_acmebot_handle_form', [$this, 'handle_form_submission']);
                add_action('admin_notices', [$this, 'display_admin_notices']);
                add_action('admin_init', [$this, 'handle_activation_redirect']);
                add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_styles']);

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
         * Enqueue admin styles
         */
        public function enqueue_admin_styles($hook_suffix): void

        {

            if (esc_html($hook_suffix) !== 'settings_page_acme-bot-integration') {
                return;
            }

            wp_enqueue_style(
                'acmebot-admin-styles',
                plugin_dir_url(__FILE__) . 'admin/admin-styles.css',
                [],
                '1.0.0'
            );
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

        public static function get_asset_url($relative_path)
        {
            return plugin_dir_url(__FILE__) . 'assets/' . $relative_path;
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

                // Handle SEO Meta Data
                $this->handle_seo_meta($result_post_id, $payload);


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
         * Handle SEO meta data for the post.
         * 
         * @param int $post_id The post ID.
         * @param array|object $payload The payload containing SEO data.
         */
        private function handle_seo_meta($post_id, $payload)
        {
            // Validate inputs
            if (!is_numeric($post_id) || $post_id <= 0) {
                return;
            }

            // Check if SEO data exists in payload
            if (!isset($payload['meta']) || !is_array($payload['meta'])) {
                return;
            }

            $seo_data = $payload['meta'];

            // Define allowed SEO fields with their validation
            $allowed_fields = [
                'title' => 'sanitize_text_field',
                'description' => 'sanitize_textarea_field',
                'keywords' => 'sanitize_text_field',
                'canonical' => 'esc_url_raw',
                'robots' => 'sanitize_text_field',
                'og_title' => 'sanitize_text_field',
                'og_description' => 'sanitize_textarea_field',
                'og_image' => 'esc_url_raw',
                'twitter_title' => 'sanitize_text_field',
                'twitter_description' => 'sanitize_textarea_field',
                'twitter_image' => 'esc_url_raw',
            ];

            // Process and validate each field
            $validated_seo_data = [];
            foreach ($allowed_fields as $field => $sanitize_callback) {
                if (isset($seo_data[$field]) && is_string($seo_data[$field])) {
                    $validated_value = call_user_func($sanitize_callback, $seo_data[$field]);
                    if (!empty($validated_value)) {
                        $validated_seo_data[$field] = $validated_value;
                    }
                }
            }

            // Only proceed if we have valid SEO data
            if (empty($validated_seo_data)) {
                return;
            }

            // Track which plugins handled the data
            $handled_by_plugin = false;

            // Handle Yoast SEO if available
            if (defined('WPSEO_VERSION') || class_exists('WPSEO_Options')) {
                $this->handle_yoast_seo($post_id, $validated_seo_data);
                $handled_by_plugin = true;
            }

            // Handle RankMath SEO if available
            if (defined('RANK_MATH_VERSION') || class_exists('RankMath')) {
                $this->handle_rankmath_seo($post_id, $validated_seo_data);
                $handled_by_plugin = true;
            }

            // Handle All in One SEO if available
            if (defined('AIOSEO_VERSION') || class_exists('AIOSEO\\Plugin\\AIOSEO')) {
                $this->handle_aioseo_seo($post_id, $validated_seo_data);
                $handled_by_plugin = true;
            }

            // Always store in our own format for fallback and consistency
            $this->handle_acme_bot_seo($post_id, $validated_seo_data);
        }

        /**
         * Handle Yoast SEO meta fields.
         * 
         * @param int $post_id Post ID.
         * @param array $seo_data Validated SEO data.
         */
        private function handle_yoast_seo($post_id, $seo_data)
        {
            $yoast_fields = [
                'title' => '_yoast_wpseo_title',
                'description' => '_yoast_wpseo_metadesc',
                'keywords' => '_yoast_wpseo_focuskw',
                'canonical' => '_yoast_wpseo_canonical',
                'robots' => '_yoast_wpseo_meta-robots-noindex',
                'og_title' => '_yoast_wpseo_opengraph-title',
                'og_description' => '_yoast_wpseo_opengraph-description',
                'og_image' => '_yoast_wpseo_opengraph-image',
                'twitter_title' => '_yoast_wpseo_twitter-title',
                'twitter_description' => '_yoast_wpseo_twitter-description',
                'twitter_image' => '_yoast_wpseo_twitter-image',
            ];

            foreach ($yoast_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) {
                    update_post_meta($post_id, $meta_key, $seo_data[$key]);
                }
            }
        }

        /**
         * Handle RankMath SEO meta fields.
         * 
         * @param int $post_id Post ID.
         * @param array $seo_data Validated SEO data.
         */
        private function handle_rankmath_seo($post_id, $seo_data)
        {
            $rankmath_fields = [
                'title' => 'rank_math_title',
                'description' => 'rank_math_description',
                'keywords' => 'rank_math_focus_keyword',
                'canonical' => 'rank_math_canonical_url',
                'robots' => 'rank_math_robots',
                'og_title' => 'rank_math_facebook_title',
                'og_description' => 'rank_math_facebook_description',
                'og_image' => 'rank_math_facebook_image',
                'twitter_title' => 'rank_math_twitter_title',
                'twitter_description' => 'rank_math_twitter_description',
                'twitter_image' => 'rank_math_twitter_image',
            ];

            foreach ($rankmath_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) {
                    update_post_meta($post_id, $meta_key, $seo_data[$key]);
                }
            }
        }

        /**
         * Handle All in One SEO meta fields.
         * 
         * @param int $post_id Post ID.
         * @param array $seo_data Validated SEO data.
         */
        private function handle_aioseo_seo($post_id, $seo_data)
        {
            $aioseo_fields = [
                'title' => '_aioseo_title',
                'description' => '_aioseo_description',
                'keywords' => '_aioseo_keywords',
                'canonical' => '_aioseo_canonical_url',
                'robots' => '_aioseo_robots_default',
                'og_title' => '_aioseo_og_title',
                'og_description' => '_aioseo_og_description',
                'og_image' => '_aioseo_og_image',
                'twitter_title' => '_aioseo_twitter_title',
                'twitter_description' => '_aioseo_twitter_description',
                'twitter_image' => '_aioseo_twitter_image',
            ];

            foreach ($aioseo_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) {
                    update_post_meta($post_id, $meta_key, $seo_data[$key]);
                }
            }
        }

        /**
         * Handle Acme Bot AI SEO meta fields (our plugin's format).
         * 
         * @param int $post_id Post ID.
         * @param array $seo_data Validated SEO data.
         */
        private function handle_acme_bot_seo($post_id, $seo_data)
        {
            $acme_fields = [
                'title' => '_acme_bot_ai_seo_title',
                'description' => '_acme_bot_ai_seo_description',
                'keywords' => '_acme_bot_ai_seo_keywords',
                'canonical' => '_acme_bot_ai_seo_canonical',
                'robots' => '_acme_bot_ai_seo_robots',
                'og_title' => '_acme_bot_ai_seo_og_title',
                'og_description' => '_acme_bot_ai_seo_og_description',
                'og_image' => '_acme_bot_ai_seo_og_image',
                'twitter_title' => '_acme_bot_ai_seo_twitter_title',
                'twitter_description' => '_acme_bot_ai_seo_twitter_description',
                'twitter_image' => '_acme_bot_ai_seo_twitter_image',
            ];

            foreach ($acme_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) {
                    update_post_meta($post_id, $meta_key, $seo_data[$key]);
                }
            }
        }

        /**
         * Get SEO meta data for a post.
         * This method retrieves SEO data regardless of which plugin stored it.
         * 
         * @param int $post_id Post ID.
         * @return array SEO data array.
         */
        public function get_post_seo_data($post_id)
        {
            if (!is_numeric($post_id) || $post_id <= 0) {
                return [];
            }

            $seo_data = [];

            // Try to get from our plugin first
            $acme_fields = [
                'title' => '_acme_bot_ai_seo_title',
                'description' => '_acme_bot_ai_seo_description',
                'keywords' => '_acme_bot_ai_seo_keywords',
                'canonical' => '_acme_bot_ai_seo_canonical',
                'robots' => '_acme_bot_ai_seo_robots',
                'og_title' => '_acme_bot_ai_seo_og_title',
                'og_description' => '_acme_bot_ai_seo_og_description',
                'og_image' => '_acme_bot_ai_seo_og_image',
                'twitter_title' => '_acme_bot_ai_seo_twitter_title',
                'twitter_description' => '_acme_bot_ai_seo_twitter_description',
                'twitter_image' => '_acme_bot_ai_seo_twitter_image',
            ];

            foreach ($acme_fields as $key => $meta_key) {
                $value = get_post_meta($post_id, $meta_key, true);
                if (!empty($value)) {
                    $seo_data[$key] = $value;
                }
            }

            return $seo_data;
        }

        /**
         * Initialize SEO hooks for frontend display when no SEO plugin is available.
         * Call this method during plugin initialization.
         */
        public function init_seo_hooks()
        {
            // Only add hooks if no major SEO plugin is active
            if (!$this->has_seo_plugin()) {
                add_action('wp_head', [$this, 'output_seo_meta_tags'], 1);
                add_filter('document_title_parts', [$this, 'filter_document_title'], 10, 1);
                add_filter('wp_title', [$this, 'filter_wp_title'], 10, 2);
            }
        }

        /**
         * Check if any major SEO plugin is active.
         * 
         * @return bool True if SEO plugin is active.
         */
        private function has_seo_plugin()
        {
            return (
                defined('WPSEO_VERSION') ||
                class_exists('WPSEO_Options') ||
                defined('RANK_MATH_VERSION') ||
                class_exists('RankMath') ||
                defined('AIOSEO_VERSION') ||
                class_exists('AIOSEO\\Plugin\\AIOSEO')
            );
        }

        /**
         * Output SEO meta tags in the head when no SEO plugin is available.
         */
        public function output_seo_meta_tags()
        {
            if (!is_singular()) {
                return;
            }

            global $post;
            $seo_data = $this->get_post_seo_data($post->ID);

            if (empty($seo_data)) {
                return;
            }

            // Meta description
            if (!empty($seo_data['description'])) {
                echo '<meta name="description" content="' . esc_attr($seo_data['description']) . '">' . "\n";
            }

            // Meta keywords
            if (!empty($seo_data['keywords'])) {
                echo '<meta name="keywords" content="' . esc_attr($seo_data['keywords']) . '">' . "\n";
            }

            // Canonical URL
            if (!empty($seo_data['canonical'])) {
                echo '<link rel="canonical" href="' . esc_url($seo_data['canonical']) . '">' . "\n";
            }

            // Robots meta
            if (!empty($seo_data['robots'])) {
                echo '<meta name="robots" content="' . esc_attr($seo_data['robots']) . '">' . "\n";
            }

            // Open Graph tags
            if (!empty($seo_data['og_title'])) {
                echo '<meta property="og:title" content="' . esc_attr($seo_data['og_title']) . '">' . "\n";
            }
            if (!empty($seo_data['og_description'])) {
                echo '<meta property="og:description" content="' . esc_attr($seo_data['og_description']) . '">' . "\n";
            }
            if (!empty($seo_data['og_image'])) {
                echo '<meta property="og:image" content="' . esc_url($seo_data['og_image']) . '">' . "\n";
            }

            // Twitter Card tags
            if (!empty($seo_data['twitter_title'])) {
                echo '<meta name="twitter:title" content="' . esc_attr($seo_data['twitter_title']) . '">' . "\n";
            }
            if (!empty($seo_data['twitter_description'])) {
                echo '<meta name="twitter:description" content="' . esc_attr($seo_data['twitter_description']) . '">' . "\n";
            }
            if (!empty($seo_data['twitter_image'])) {
                echo '<meta name="twitter:image" content="' . esc_url($seo_data['twitter_image']) . '">' . "\n";
                echo '<meta name="twitter:card" content="summary_large_image">' . "\n";
            }
        }

        /**
         * Filter the document title when no SEO plugin is available.
         * 
         * @param array $title The document title parts.
         * @return array Modified title parts.
         */
        public function filter_document_title($title)
        {
            if (!is_singular()) {
                return $title;
            }

            global $post;
            $seo_data = $this->get_post_seo_data($post->ID);

            if (!empty($seo_data['title'])) {
                $title['title'] = $seo_data['title'];
            }

            return $title;
        }

        /**
         * Filter wp_title when no SEO plugin is available (fallback for older themes).
         * 
         * @param string $title The page title.
         * @param string $sep The title separator.
         * @return string Modified title.
         */
        public function filter_wp_title($title, $sep)
        {
            if (!is_singular()) {
                return $title;
            }

            global $post;
            $seo_data = $this->get_post_seo_data($post->ID);

            if (!empty($seo_data['title'])) {
                return $seo_data['title'] . ' ' . $sep . ' ' . get_bloginfo('name');
            }

            return $title;
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
