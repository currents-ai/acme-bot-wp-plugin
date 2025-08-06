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
 *
 * @package AcmeBot
 */

// Prevent direct access.
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants.
define('ACMEBOT_VERSION', '1.0.3');
define('ACMEBOT_PLUGIN_FILE', __FILE__);
define('ACMEBOT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ACMEBOT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('ACMEBOT_PLUGIN_BASENAME', plugin_basename(__FILE__));

if (!class_exists('AcmeBot')) {
    /**
     * Main AcmeBot Class.
     *
     * @since 1.0.0
     */
    class AcmeBot
    {

        /**
         * REST API version.
         * @var int
         */
        const REST_VERSION = 1;

        /**
         * Option name for secret key storage.
         * @var string
         */
        const SECRET_OPTION = 'acmebot_secret';

        /**
         * Option name for the user ID who initiated integration.
         * @var string
         */
        const INTEGRATING_USER_ID_OPTION = 'acmebot_default_author_id';

        /**
         * Option name for integration completion flag.
         * @var string
         */
        const IS_INTEGRATION_COMPLETED = 'acmebot_integration_completed';

        /**
         * Default admin user ID.
         * @var int
         */
        const DEFAULT_AUTHOR_ID = 1;

        /**
         * Base URL for API endpoints.
         * @var string
         */
        const BASE_URL = 'https://acme.bot';

        /**
         * API authorization URL template.
         * @var string
         */
        const ACMEBOT_API_AUTHORIZE_URL = self::BASE_URL . '/d/{cust_id}/connectors/create';

        /**
         * API host domain.
         * @var string
         */
        const ACMEBOT_API_HOST = 'acme.bot';

        /**
         * Log table name suffix.
         * @var string
         */
        const LOG_TABLE = 'acmebot_logs';

        /**
         * Plugin instance.
         * @var AcmeBot|null
         */
        private static $instance = null;

        /**
         * Get plugin instance.
         *
         * @return AcmeBot
         */
        public static function get_instance()
        {
            if (null === self::$instance) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        private function __construct()
        {
            $this->init_hooks();
        }

        /**
         * Initialize hooks.
         */
        private function init_hooks()
        {
            add_action('rest_api_init', [$this, 'register_rest_routes']);
            add_action('init', [$this, 'init_seo_hooks']);

            if (is_admin()) {
                add_filter('plugin_action_links_' . ACMEBOT_PLUGIN_BASENAME, [$this, 'add_settings_link']);
                add_filter('allowed_redirect_hosts', [$this, 'add_acmebot_allowed_host']);
                add_action('admin_menu', [$this, 'add_plugin_page']);
                add_action('admin_post_acmebot_handle_form', [$this, 'handle_form_submission']);
                add_action('admin_notices', [$this, 'display_admin_notices']);
                add_action('admin_init', [$this, 'handle_activation_redirect']);
                add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_styles']);

                // CORS headers for REST API.
                add_filter('rest_pre_serve_request', [$this, 'add_cors_headers'], 10, 2);
            }

            register_activation_hook(ACMEBOT_PLUGIN_FILE, [__CLASS__, 'activate']);
            register_deactivation_hook(ACMEBOT_PLUGIN_FILE, [__CLASS__, 'deactivate']);
        }

        /**
         * Add CORS headers for REST API requests.
         *
         * @param bool  $served Whether the request has already been served.
         * @param mixed $result The response data.
         * @return bool
         */
        public function add_cors_headers($served, $result)
        {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, x-secret');
            return $served;
        }

        /**
         * Enqueue admin styles.
         *
         * @param string $hook_suffix The current admin page.
         */
        public function enqueue_admin_styles($hook_suffix)
        {
            if ('settings_page_acme-bot-integration' !== esc_html($hook_suffix)) {
                return;
            }

            wp_enqueue_style(
                'acmebot-admin-styles',
                ACMEBOT_PLUGIN_URL . 'admin/admin-styles.css',
                [],
                ACMEBOT_VERSION
            );
        }

        /**
         * Plugin activation callback.
         */
        public static function activate()
        {
            set_transient('acmebot_activation_redirect', true, 30);

            if (!get_option(self::INTEGRATING_USER_ID_OPTION)) {
                update_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
            }

            self::create_logs_table();
        }

        /**
         * Plugin deactivation callback.
         */
        public static function deactivate()
        {
            delete_option(self::SECRET_OPTION);
            delete_option(self::INTEGRATING_USER_ID_OPTION);
            delete_option(self::IS_INTEGRATION_COMPLETED);
            delete_transient('acmebot_settings_errors');
            delete_transient('acmebot_activation_redirect');
        }

        /**
         * Create logs table on activation.
         */
        private static function create_logs_table()
        {
            try {
                global $wpdb;
                $table_name      = $wpdb->prefix . self::LOG_TABLE;
                $charset_collate = $wpdb->get_charset_collate();

                $sql = "CREATE TABLE {$table_name} (
                    id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                    timestamp datetime DEFAULT CURRENT_TIMESTAMP,
                    level varchar(20) NOT NULL DEFAULT 'info',
                    endpoint varchar(255) NOT NULL,
                    method varchar(10) NOT NULL,
                    request_data longtext DEFAULT NULL,
                    response_data longtext DEFAULT NULL,
                    response_code int(3) UNSIGNED DEFAULT NULL,
                    execution_time float DEFAULT NULL,
                    error_message text DEFAULT NULL,
                    post_id bigint(20) UNSIGNED DEFAULT NULL,
                    PRIMARY KEY (id),
                    KEY level (level),
                    KEY endpoint (endpoint),
                    KEY response_code (response_code),
                    KEY post_id (post_id)
                ) {$charset_collate};";

                require_once ABSPATH . 'wp-admin/includes/upgrade.php';
                dbDelta($sql);
            } catch (Exception $e) {
                // error_log('AcmeBot: Failed to create logs table: ' . $e->getMessage());

            }
        }

        /**
         * Log webhook activity.
         */
        private function log_webhook_activity($endpoint, $method, $request_data = null, $response_data = null, $response_code = 200, $execution_time = 0, $error_message = null, $post_id = null, $level = 'info')
        {
            try {
                global $wpdb;
                $table_name = $wpdb->prefix . self::LOG_TABLE;
                $log_data = [
                    'timestamp'      => current_time('mysql', true),
                    'level'          => sanitize_text_field($level),
                    'endpoint'       => sanitize_text_field($endpoint),
                    'method'         => sanitize_text_field($method),
                    'request_data'   => (is_array($request_data) || is_object($request_data)) ? wp_json_encode($request_data) : $request_data,
                    'response_data'  => (is_array($response_data) || is_object($response_data)) ? wp_json_encode($response_data) : $response_data,
                    'response_code'  => absint($response_code),
                    'execution_time' => floatval($execution_time),
                    'error_message'  => $error_message ? sanitize_textarea_field($error_message) : null,
                    'post_id'        => $post_id ? absint($post_id) : null,
                ];
                $wpdb->insert($table_name, $log_data); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            } catch (Throwable $e) {
                // Logging should not crash the main process. Intentionally left empty to ensure the API request succeeds even if logging fails.
            }
        }

        /**
         * Handle activation redirect to settings page.
         */
        public function handle_activation_redirect()
        {
            if (get_transient('acmebot_activation_redirect')) {
                delete_transient('acmebot_activation_redirect');
                wp_safe_redirect(
                    add_query_arg(
                        [
                            'page'                   => 'acme-bot-integration',
                            'acmebot_just_activated' => '1',
                            'acmebot_nonce'          => wp_create_nonce('acmebot_admin_notices'),
                        ],
                        admin_url('options-general.php')
                    )
                );
                exit;
            }
        }

        /**
         * Get asset URL.
         */
        public static function get_asset_url($relative_path)
        {
            return ACMEBOT_PLUGIN_URL . 'assets/' . $relative_path;
        }

        /**
         * Register REST API routes.
         */
        public function register_rest_routes()
        {
            $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';

            register_rest_route(
                $namespace,
                '/posts',
                [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'create_post'],
                    'permission_callback' => '__return_true',
                    'args'                => [
                        'payload' => [
                            'required'    => true,
                            'type'        => 'object',
                            'description' => 'The data associated with the post.',
                            'properties'  => [
                                'title'      => ['type' => 'string'],
                                'content'    => ['type' => 'string'],
                                'user_id'    => ['type' => 'integer'],
                                'user_name'  => ['type' => 'string'],
                                'categories' => [
                                    'type'  => 'array',
                                    'items' => ['type' => ['string', 'integer']],
                                ],
                            ],
                        ],
                    ],
                ]
            );

            register_rest_route(
                $namespace,
                '/verify',
                [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'handle_verification'],
                    'permission_callback' => '__return_true',
                    'args'                => [
                        'verification_token' => [
                            'required'    => false,
                            'type'        => 'string',
                            'description' => 'Optional verification token.',
                        ],
                    ],
                ]
            );

            register_rest_route(
                $namespace,
                '/logs',
                [
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => [$this, 'get_logs'],
                    'permission_callback' => '__return_true',
                    'args'                => [
                        'limit'     => [
                            'required' => false,
                            'type'     => 'integer',
                            'default'  => 50,
                            'minimum'  => 1,
                            'maximum'  => 1000,
                        ],
                        'offset'    => [
                            'required' => false,
                            'type'     => 'integer',
                            'default'  => 0,
                            'minimum'  => 0,
                        ],
                        'level'     => [
                            'required' => false,
                            'type'     => 'string',
                            'enum'     => ['info', 'warning', 'error'],
                        ],
                        'endpoint'  => [
                            'required' => false,
                            'type'     => 'string',
                        ],
                        'date_from' => [
                            'required' => false,
                            'type'     => 'string',
                        ],
                        'date_to'   => [
                            'required' => false,
                            'type'     => 'string',
                        ],
                    ],
                ]
            );
        }

        /**
         * Get logs endpoint handler.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function get_logs(WP_REST_Request $request)
        {
            $start_time = microtime(true);
            $endpoint   = '/logs';
            $method     = 'GET';

            try {
                $verification_result = $this->verify_secret($request);
                if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $verification_result, 401, microtime(true) - $start_time, 'Authentication failed', null, 'error');
                    return $verification_result;
                }

                global $wpdb;
                $table_name = $wpdb->prefix . self::LOG_TABLE;

                $limit           = absint($request->get_param('limit'));
                $offset          = absint($request->get_param('offset'));
                $level           = sanitize_text_field($request->get_param('level'));
                $endpoint_filter = sanitize_text_field($request->get_param('endpoint'));
                $date_from       = sanitize_text_field($request->get_param('date_from'));
                $date_to         = sanitize_text_field($request->get_param('date_to'));

                $where_conditions = [];
                $where_values     = [];

                if (!empty($level)) {
                    $where_conditions[] = 'level = %s';
                    $where_values[]     = $level;
                }
                if (!empty($endpoint_filter)) {
                    $where_conditions[] = 'endpoint LIKE %s';
                    $where_values[]     = '%' . $wpdb->esc_like($endpoint_filter) . '%';
                }
                if (!empty($date_from)) {
                    $where_conditions[] = 'timestamp >= %s';
                    $where_values[]     = $date_from;
                }
                if (!empty($date_to)) {
                    $where_conditions[] = 'timestamp <= %s';
                    $where_values[]     = $date_to;
                }


                // Build WHERE clause
                $where_clause = '';

                if (!empty($where_conditions)) {
                    $where_clause = ' WHERE ' . implode(' AND ', $where_conditions);
                }

                // Build count query
                $count_sql = "SELECT COUNT(*) FROM {$table_name}{$where_clause}";
                $count_query = !empty($where_values) ? $wpdb->prepare($count_sql, $where_values) : $count_sql; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $total_count = $wpdb->get_var($count_query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared

                // Build main query with pagination
                $query_sql = "SELECT * FROM {$table_name}{$where_clause} ORDER BY timestamp DESC LIMIT %d OFFSET %d";
                $query_values = array_merge($where_values, [$limit, $offset]);
                $query = $wpdb->prepare($query_sql, $query_values); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
                $logs = $wpdb->get_results($query, ARRAY_A); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared

                // Decode request/response JSON if valid

                foreach ($logs as &$log) {
                    if (!empty($log['request_data']) && ($decoded = json_decode($log['request_data'], true)) && JSON_ERROR_NONE === json_last_error()) {
                        $log['request_data'] = $decoded;
                    }
                    if (!empty($log['response_data']) && ($decoded = json_decode($log['response_data'], true)) && JSON_ERROR_NONE === json_last_error()) {
                        $log['response_data'] = $decoded;
                    }
                }

                $pagination = [
                    'total'    => intval($total_count),
                    'limit'    => $limit,
                    'offset'   => $offset,
                    'has_more' => ($offset + $limit) < $total_count,
                ];

                $response_data = [
                    'status' => 'SUCCESS',
                    'data'   => [
                        'logs'       => $logs,
                        'pagination' => $pagination,
                    ],
                ];

                return new WP_REST_Response($response_data, 200);
            } catch (Exception $e) {
                $error_response = ['status' => 'ERROR', 'message' => 'An unexpected error occurred: ' . $e->getMessage()];
                $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 500, microtime(true) - $start_time, $e->getMessage(), null, 'error');
                return new WP_REST_Response($error_response, 500);
            }
        }

        /**
         * Handle webhook requests for post creation.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function create_post(WP_REST_Request $request)
        {
            $start_time = microtime(true);
            $endpoint   = '/posts';
            $method     = 'POST';

            try {
                $verification_result = $this->verify_secret($request);
                if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $verification_result, 401, microtime(true) - $start_time, 'Authentication failed', null, 'error');
                    return $verification_result;
                }

                if (!get_option(self::IS_INTEGRATION_COMPLETED, false)) {
                    $error_response = ['status' => 'ERROR', 'message' => 'Integration not created or verified.'];
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 403, microtime(true) - $start_time, 'Integration not completed', null, 'error');
                    return new WP_REST_Response($error_response, 403);
                }

                $payload = $request->get_param('payload');
                if (empty($payload)) {
                    $error_response = ['status' => 'ERROR', 'message' => 'Missing required parameter: payload'];
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 400, microtime(true) - $start_time, 'Missing payload', null, 'error');
                    return new WP_REST_Response($error_response, 400);
                }

                $response       = $this->handle_create_post($payload);
                $execution_time = microtime(true) - $start_time;

                $post_id       = null;
                $response_data = $response->get_data();
                if (isset($response_data['data']['post_id'])) {
                    $post_id = $response_data['data']['post_id'];
                }

                $level         = $response->get_status() >= 400 ? 'error' : 'info';
                $error_message = 'error' === $level ? $response_data['message'] : null;

                $this->log_webhook_activity($endpoint, $method, $request->get_params(), $response_data, $response->get_status(), $execution_time, $error_message, $post_id, $level);
                return $response;
            } catch (Exception $e) {
                $error_response = ['status' => 'ERROR', 'message' => 'Error processing webhook: ' . $e->getMessage()];
                $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 500, microtime(true) - $start_time, $e->getMessage(), null, 'error');
                return new WP_REST_Response($error_response, 500);
            }
        }

        /**
         * Handle the create_post event logic.
         *
         * @param array|object $payload The payload for the create_post event.
         * @return WP_REST_Response Response object.
         */
        private function handle_create_post($payload)
        {
            try {
                $is_update     = isset($payload['post_id']) && is_numeric($payload['post_id']) && $payload['post_id'] > 0;
                $post_id       = $is_update ? absint($payload['post_id']) : 0;
                $existing_post = null;

                if ($is_update) {
                    $existing_post = get_post($post_id);
                    if (!$existing_post) {
                        return new WP_REST_Response(['status' => 'ERROR', 'message' => 'Invalid post_id: Post does not exist.'], 404);
                    }
                }

                $title   = isset($payload['title']) ? $payload['title'] : null;
                $content = isset($payload['content']) ? $payload['content'] : null;

                if (!$is_update && (empty($title) || !isset($content))) {
                    return new WP_REST_Response(['status' => 'ERROR', 'message' => 'Invalid payload: title and content are required for new posts.'], 400);
                }

                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
                if ($is_update && $existing_post) {
                    $author_id = $existing_post->post_author;
                }
                if ($potential_author_id = $this->get_author_from_payload($payload)) {
                    if ($this->user_can_publish($potential_author_id)) {
                        $author_id = $potential_author_id;
                    }
                }

                $category_ids = $this->process_categories($payload);

                $post_data = [
                    'post_status' => isset($payload['post_status']) ? $payload['post_status'] : ($is_update ? $existing_post->post_status : 'publish'),
                    'post_type'   => isset($payload['post_type']) ? $payload['post_type'] : ($is_update ? $existing_post->post_type : 'post'),
                    'post_author' => $author_id,
                ];

                if (isset($title)) $post_data['post_title'] = sanitize_text_field($title);
                if (isset($content)) $post_data['post_content'] = wp_kses_post($content);
                if (!empty($category_ids)) $post_data['post_category'] = $category_ids;

                if ($is_update) {
                    $post_data['ID'] = $post_id;
                } else {
                    $post_data['post_title']   = $post_data['post_title'] ?? 'Untitled Post';
                    $post_data['post_content'] = $post_data['post_content'] ?? '';
                }

                $result_post_id = wp_insert_post($post_data, true);

                if (is_wp_error($result_post_id)) {
                    $action = $is_update ? 'update' : 'create';
                    return new WP_REST_Response(['status' => 'ERROR', 'message' => 'Failed to ' . $action . ' post: ' . $result_post_id->get_error_message()], 500);
                }

                $this->handle_seo_meta($result_post_id, $payload);

                $action      = $is_update ? 'updated' : 'created';
                $status_code = $is_update ? 200 : 201;

                return new WP_REST_Response(
                    [
                        'status'  => 'SUCCESS',
                        'message' => 'Post ' . $action . ' successfully',
                        'data'    => ['post_id' => $result_post_id, 'url' => get_permalink($result_post_id)],
                    ],
                    $status_code
                );
            } catch (Exception $e) {
                return new WP_REST_Response(['status' => 'ERROR', 'message' => 'Error handling post creation/update: ' . $e->getMessage()], 500);
            }
        }

        /**
         * Get author ID from payload.
         *
         * @param array|object $payload The payload data.
         * @return int|null Author ID if found and valid, null otherwise.
         */
        private function get_author_from_payload($payload)
        {
            if (isset($payload['user_id']) && is_numeric($payload['user_id']) && absint($payload['user_id']) > 0) {
                return absint($payload['user_id']);
            }

            if (isset($payload['user_name']) && is_string($payload['user_name']) && !empty(trim($payload['user_name']))) {
                $username = sanitize_user(trim($payload['user_name']));
                $user     = get_user_by('login', $username);

                if (!$user) {
                    $users = get_users(['search' => $username, 'search_columns' => ['display_name'], 'number' => 1]);
                    $user  = !empty($users) ? $users[0] : null;
                }
                return $user ? $user->ID : null;
            }
            return null;
        }

        /**
         * Check if user can publish posts.
         */
        private function user_can_publish($user_id)
        {
            return get_user_by('ID', $user_id) && user_can($user_id, 'publish_posts') && user_can($user_id, 'edit_posts');
        }

        /**
         * Process categories from payload.
         *
         * @param array|object $payload The payload data.
         * @return array Array of category IDs.
         */
        private function process_categories($payload)
        {
            $category_ids = [];
            if (!isset($payload['categories']) || !is_array($payload['categories'])) {
                return $category_ids;
            }

            foreach ($payload['categories'] as $category_ref) {
                $cat_id = 0;
                if (is_int($category_ref) || (is_string($category_ref) && is_numeric($category_ref))) {
                    $term = term_exists(absint($category_ref), 'category');
                    if (0 !== $term && null !== $term) $cat_id = (int) $term['term_id'];
                } elseif (is_string($category_ref) && !empty(trim($category_ref))) {
                    $category_name = sanitize_text_field(trim($category_ref));
                    $term          = term_exists($category_name, 'category');
                    if (0 !== $term && null !== $term) {
                        $cat_id = (int) $term['term_id'];
                    } else {
                        $new_cat = wp_insert_term($category_name, 'category');
                        if (!is_wp_error($new_cat) && isset($new_cat['term_id'])) $cat_id = (int) $new_cat['term_id'];
                    }
                }
                if ($cat_id > 0 && !in_array($cat_id, $category_ids, true)) $category_ids[] = $cat_id;
            }
            return $category_ids;
        }

        /**
         * Handle SEO meta data for the post.
         */
        private function handle_seo_meta($post_id, $payload)
        {
            if (!is_numeric($post_id) || $post_id <= 0 || !isset($payload['meta']) || !is_array($payload['meta'])) {
                return;
            }
            $seo_data = $payload['meta'];

            $allowed_fields = [
                'title'               => 'sanitize_text_field',
                'description' => 'sanitize_textarea_field',
                'keywords' => 'sanitize_text_field',
                'canonical'           => 'esc_url_raw',
                'robots' => 'sanitize_text_field',
                'og_title' => 'sanitize_text_field',
                'og_description'      => 'sanitize_textarea_field',
                'og_image' => 'esc_url_raw',
                'twitter_title' => 'sanitize_text_field',
                'twitter_description' => 'sanitize_textarea_field',
                'twitter_image' => 'esc_url_raw',
                'author' => 'sanitize_text_field',
            ];

            $validated_seo_data = [];
            foreach ($allowed_fields as $field => $sanitize_callback) {
                if (isset($seo_data[$field]) && is_string($seo_data[$field])) {
                    $validated_value = call_user_func($sanitize_callback, $seo_data[$field]);
                    if (!empty($validated_value)) $validated_seo_data[$field] = $validated_value;
                }
            }
            if (empty($validated_seo_data)) return;

            if ($this->is_yoast_active()) $this->handle_yoast_seo($post_id, $validated_seo_data);
            if ($this->is_rankmath_active()) $this->handle_rankmath_seo($post_id, $validated_seo_data);
            if ($this->is_aioseo_active()) $this->handle_aioseo_seo($post_id, $validated_seo_data);

            // Always store in our own format for fallback.
            $this->handle_acme_bot_seo($post_id, $validated_seo_data);
        }

        private function is_yoast_active()
        {
            return defined('WPSEO_VERSION') || class_exists('WPSEO_Options');
        }
        private function is_rankmath_active()
        {
            return defined('RANK_MATH_VERSION') || class_exists('RankMath');
        }
        private function is_aioseo_active()
        {
            return defined('AIOSEO_VERSION') || class_exists('AIOSEO\\Plugin\\AIOSEO');
        }
        private function has_seo_plugin()
        {
            return $this->is_yoast_active() || $this->is_rankmath_active() || $this->is_aioseo_active();
        }

        private function handle_yoast_seo($post_id, $seo_data)
        {
            $yoast_fields = ['title' => '_yoast_wpseo_title', 'description' => '_yoast_wpseo_metadesc', 'keywords' => '_yoast_wpseo_focuskw', 'canonical' => '_yoast_wpseo_canonical', 'robots' => '_yoast_wpseo_meta-robots-noindex', 'og_title' => '_yoast_wpseo_opengraph-title', 'og_description' => '_yoast_wpseo_opengraph-description', 'og_image' => '_yoast_wpseo_opengraph-image', 'twitter_title' => '_yoast_wpseo_twitter-title', 'twitter_description' => '_yoast_wpseo_twitter-description', 'twitter_image' => '_yoast_wpseo_twitter-image', 'author' => '_yoast_wpseo_meta_author'];
            foreach ($yoast_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) update_post_meta($post_id, $meta_key, $seo_data[$key]);
            }
        }
        private function handle_rankmath_seo($post_id, $seo_data)
        {
            $rankmath_fields = ['title' => 'rank_math_title', 'description' => 'rank_math_description', 'keywords' => 'rank_math_focus_keyword', 'canonical' => 'rank_math_canonical_url', 'robots' => 'rank_math_robots', 'og_title' => 'rank_math_facebook_title', 'og_description' => 'rank_math_facebook_description', 'og_image' => 'rank_math_facebook_image', 'twitter_title' => 'rank_math_twitter_title', 'twitter_description' => 'rank_math_twitter_description', 'twitter_image' => 'rank_math_twitter_image', 'author' => 'rank_math_author'];
            foreach ($rankmath_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) update_post_meta($post_id, $meta_key, $seo_data[$key]);
            }
        }
        private function handle_aioseo_seo($post_id, $seo_data)
        {
            $aioseo_fields = ['title' => '_aioseo_title', 'description' => '_aioseo_description', 'keywords' => '_aioseo_keywords', 'canonical' => '_aioseo_canonical_url', 'robots' => '_aioseo_robots_default', 'og_title' => '_aioseo_og_title', 'og_description' => '_aioseo_og_description', 'og_image' => '_aioseo_og_image', 'twitter_title' => '_aioseo_twitter_title', 'twitter_description' => '_aioseo_twitter_description', 'twitter_image' => '_aioseo_twitter_image', 'author' => '_aioseo_author'];
            foreach ($aioseo_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) update_post_meta($post_id, $meta_key, $seo_data[$key]);
            }
        }
        private function handle_acme_bot_seo($post_id, $seo_data)
        {
            $acme_fields = ['title' => '_acme_bot_ai_seo_title', 'description' => '_acme_bot_ai_seo_description', 'keywords' => '_acme_bot_ai_seo_keywords', 'canonical' => '_acme_bot_ai_seo_canonical', 'robots' => '_acme_bot_ai_seo_robots', 'og_title' => '_acme_bot_ai_seo_og_title', 'og_description' => '_acme_bot_ai_seo_og_description', 'og_image' => '_acme_bot_ai_seo_og_image', 'twitter_title' => '_acme_bot_ai_seo_twitter_title', 'twitter_description' => '_acme_bot_ai_seo_twitter_description', 'twitter_image' => '_acme_bot_ai_seo_twitter_image', 'author' => '_acme_bot_ai_seo_author'];
            foreach ($acme_fields as $key => $meta_key) {
                if (isset($seo_data[$key])) update_post_meta($post_id, $meta_key, $seo_data[$key]);
            }
        }

        /**
         * Get SEO meta data for a post.
         *
         * @param int $post_id Post ID.
         * @return array SEO data array.
         */
        public function get_post_seo_data($post_id)
        {
            if (!is_numeric($post_id) || $post_id <= 0) return [];
            $seo_data = [];
            $acme_fields = ['title' => '_acme_bot_ai_seo_title', 'description' => '_acme_bot_ai_seo_description', 'keywords' => '_acme_bot_ai_seo_keywords', 'canonical' => '_acme_bot_ai_seo_canonical', 'robots' => '_acme_bot_ai_seo_robots', 'og_title' => '_acme_bot_ai_seo_og_title', 'og_description' => '_acme_bot_ai_seo_og_description', 'og_image' => '_acme_bot_ai_seo_og_image', 'twitter_title' => '_acme_bot_ai_seo_twitter_title', 'twitter_description' => '_acme_bot_ai_seo_twitter_description', 'twitter_image' => '_acme_bot_ai_seo_twitter_image', 'author' => '_acme_bot_ai_seo_author'];
            foreach ($acme_fields as $key => $meta_key) {
                $value = get_post_meta($post_id, $meta_key, true);
                if (!empty($value)) $seo_data[$key] = $value;
            }
            return $seo_data;
        }

        /**
         * Initialize SEO hooks for frontend display.
         */
        public function init_seo_hooks()
        {
            if (!$this->has_seo_plugin()) {
                add_action('wp_head', [$this, 'output_seo_meta_tags'], 1);
                add_filter('document_title_parts', [$this, 'filter_document_title'], 10, 1);
                add_filter('wp_title', [$this, 'filter_wp_title'], 10, 2);
            }
        }

        /**
         * Output SEO meta tags in the head if no other SEO plugin is active.
         */
        public function output_seo_meta_tags()
        {
            if (!is_singular()) return;

            global $post;
            $seo_data = $this->get_post_seo_data($post->ID);
            if (empty($seo_data)) return;

            if (!empty($seo_data['description'])) printf('<meta name="description" content="%s">' . "\n", esc_attr($seo_data['description']));
            if (!empty($seo_data['keywords'])) printf('<meta name="keywords" content="%s">' . "\n", esc_attr($seo_data['keywords']));
            if (!empty($seo_data['author'])) printf('<meta name="author" content="%s">' . "\n", esc_attr($seo_data['author']));
            if (!empty($seo_data['canonical'])) printf('<link rel="canonical" href="%s">' . "\n", esc_url($seo_data['canonical']));
            if (!empty($seo_data['robots'])) printf('<meta name="robots" content="%s">' . "\n", esc_attr($seo_data['robots']));
            if (!empty($seo_data['og_title'])) printf('<meta property="og:title" content="%s">' . "\n", esc_attr($seo_data['og_title']));
            if (!empty($seo_data['og_description'])) printf('<meta property="og:description" content="%s">' . "\n", esc_attr($seo_data['og_description']));
            if (!empty($seo_data['og_image'])) printf('<meta property="og:image" content="%s">' . "\n", esc_url($seo_data['og_image']));
            if (!empty($seo_data['twitter_title'])) printf('<meta name="twitter:title" content="%s">' . "\n", esc_attr($seo_data['twitter_title']));
            if (!empty($seo_data['twitter_description'])) printf('<meta name="twitter:description" content="%s">' . "\n", esc_attr($seo_data['twitter_description']));
            if (!empty($seo_data['twitter_image'])) {
                printf('<meta name="twitter:image" content="%s">' . "\n", esc_url($seo_data['twitter_image']));
                echo '<meta name="twitter:card" content="summary_large_image">' . "\n";
            }
        }

        /**
         * Filter the document title.
         */
        public function filter_document_title($title)
        {
            if (is_singular()) {
                global $post;
                $seo_data = $this->get_post_seo_data($post->ID);
                if (!empty($seo_data['title'])) $title['title'] = $seo_data['title'];
            }
            return $title;
        }

        /**
         * Filter wp_title for older themes.
         */
        public function filter_wp_title($title, $sep)
        {
            if (is_singular()) {
                global $post;
                $seo_data = $this->get_post_seo_data($post->ID);
                if (!empty($seo_data['title'])) return $seo_data['title'] . ' ' . $sep . ' ' . get_bloginfo('name');
            }
            return $title;
        }

        /**
         * Handle form submission from settings page.
         */
        public function handle_form_submission()
        {
            $errors = [];
            if (!isset($_POST['acmebot_settings_nonce']) || !wp_verify_nonce(sanitize_key($_POST['acmebot_settings_nonce']), 'acmebot_settings_action')) {
                $errors[] = 'Security check failed. Please try submitting the form again.';
            }
            if (!current_user_can('manage_options')) $errors[] = 'You do not have permission to manage options.';
            if (!current_user_can('publish_posts') || !current_user_can('edit_posts')) $errors[] = 'You need permissions to publish and edit posts to set up this integration.';

            $integrating_user_id = get_current_user_id();
            if ($integrating_user_id <= 0) $errors[] = 'Could not identify the current logged-in user.';

            if (!empty($errors)) {
                set_transient('acmebot_settings_errors', $errors, 300);
                wp_safe_redirect(add_query_arg(['acmebot_error' => '1', 'acmebot_nonce' => wp_create_nonce('acmebot_admin_notices')], admin_url('options-general.php?page=acme-bot-integration')));
                exit;
            }

            try {
                update_option(self::INTEGRATING_USER_ID_OPTION, $integrating_user_id);
                $secret = wp_generate_password(128, false);
                update_option(self::SECRET_OPTION, $secret);

                $namespace = 'acmebot/v' . self::REST_VERSION . '/webhook';
                $acme_auth_url = add_query_arg(
                    urlencode_deep([
                        'form_data.webhook_url'         => rest_url($namespace),
                        'form_data.verify_url'          => rest_url($namespace . '/verify'),
                        'form_data.post_url'            => rest_url($namespace . '/posts'),
                        'form_data.logs_url'            => rest_url($namespace . '/logs'),
                        'form_data.secret'              => $secret,
                        'form_data.username'            => wp_get_current_user()->user_login,
                        'form_data.site'                => site_url(),
                        'form_data.connector_flow_type' => 'CONNECTOR_WORDPRESS_PLUGIN',
                        'update_form'                   => 'false',
                        'flow_type'                     => 'CONNECTOR',
                    ]),
                    urlencode(self::ACMEBOT_API_AUTHORIZE_URL)
                );
                wp_safe_redirect(add_query_arg('redirect_path', urlencode($acme_auth_url), self::BASE_URL . '/login'));
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
        public function add_settings_link(array $links)
        {
            $settings_link = sprintf('<a href="%s">%s</a>', esc_url(admin_url('options-general.php?page=acme-bot-integration')), 'Settings');
            array_unshift($links, $settings_link);
            return $links;
        }

        /**
         * Add AcmeBot API host to allowed redirect hosts.
         */
        public function add_acmebot_allowed_host(array $hosts)
        {
            if (!in_array(self::ACMEBOT_API_HOST, $hosts, true)) $hosts[] = self::ACMEBOT_API_HOST;
            return $hosts;
        }

        /**
         * Add plugin admin page.
         */
        public function add_plugin_page()
        {
            add_options_page('Acme Bot Settings', 'Acme Bot', 'manage_options', 'acme-bot-integration', [$this, 'render_admin_page']);
        }

        /**
         * Render the admin settings page.
         */
        public function render_admin_page()
        {
            $template_path = ACMEBOT_PLUGIN_DIR . 'admin/admin-settings-page.php';
            if (file_exists($template_path)) {
                include $template_path;
            } else {
                printf('<div class="wrap"><h1>%s</h1><div class="notice notice-error"><p>%s</p></div></div>', 'Acme Bot Settings', 'Error: Settings page template not found at <code>' . esc_html($template_path) . '</code>');
            }
        }

        /**
         * Display admin notices.
         */
        public function display_admin_notices()
        {
            $nonce_action = 'acmebot_admin_notices';
            $has_valid_nonce = isset($_GET['acmebot_nonce']) && wp_verify_nonce(sanitize_key($_GET['acmebot_nonce']), $nonce_action);

            if (isset($_GET['acmebot_error']) && '1' === $_GET['acmebot_error'] && $has_valid_nonce) {
                $errors = get_transient('acmebot_settings_errors');
                if ($errors && is_array($errors)) {
                    foreach ($errors as $error) printf('<div class="notice notice-error is-dismissible"><p>%s</p></div>', esc_html($error));
                    delete_transient('acmebot_settings_errors');
                }
            }
            if (isset($_GET['acmebot_just_activated']) && '1' === $_GET['acmebot_just_activated'] && $has_valid_nonce) {
                if (!get_option(self::SECRET_OPTION)) {
                    printf('<div class="notice notice-info is-dismissible"><p>%s</p></div>', 'Welcome to AcmeBot! Please click the "Connect to AcmeBot" button below to complete the setup.');
                }
            }
        }

        /**
         * Verify the request secret header.
         *
         * @param WP_REST_Request $request The request object.
         * @return bool|WP_REST_Response True if valid, WP_REST_Response on failure.
         */
        private function verify_secret(WP_REST_Request $request)
        {
            $received_secret = $request->get_header('x-secret');
            $stored_secret   = get_option(self::SECRET_OPTION);
            if (empty($received_secret) || empty($stored_secret) || !hash_equals((string) $stored_secret, (string) $received_secret)) {
                return new WP_REST_Response(['status' => 'ERROR', 'message' => 'Unauthorized: Invalid or missing secret.'], 401);
            }
            return true;
        }

        /**
         * Handle verification requests from AcmeBot.
         *
         * @param WP_REST_Request $request Full data about the request.
         * @return WP_REST_Response Response object.
         */
        public function handle_verification(WP_REST_Request $request)
        {
            $start_time = microtime(true);
            $endpoint   = '/verify';
            $method     = 'POST';

            try {
                $verification_result = $this->verify_secret($request);
                if (is_wp_error($verification_result) || $verification_result instanceof WP_REST_Response) {
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $verification_result, 401, microtime(true) - $start_time, 'Authentication failed', null, 'error');
                    return $verification_result;
                }

                $author_id = get_option(self::INTEGRATING_USER_ID_OPTION, self::DEFAULT_AUTHOR_ID);
                if (!get_user_by('ID', $author_id)) {
                    $error_response = ['status' => 'ERROR', 'message' => 'Verification failed: Configured author user ID is invalid.'];
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 403, microtime(true) - $start_time, 'Invalid author ID', null, 'error');
                    return new WP_REST_Response($error_response, 403);
                }

                $test_post_data = ['post_title' => 'AcmeBot Verification Post - ' . time(), 'post_content' => 'This is a temporary post for verification.', 'post_status' => 'draft', 'post_author' => $author_id];
                $test_post_id = wp_insert_post($test_post_data, true);

                if (is_wp_error($test_post_id)) {
                    $status_code = in_array($test_post_id->get_error_code(), ['insufficient_permissions', 'invalid_author'], true) ? 403 : 500;
                    $error_response = ['status' => 'ERROR', 'message' => 'Verification failed: Could not create test post. Error: ' . $test_post_id->get_error_message()];
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, $status_code, microtime(true) - $start_time, $test_post_id->get_error_message(), null, 'error');
                    return new WP_REST_Response($error_response, $status_code);
                }

                if (!wp_delete_post($test_post_id, true)) {
                    wp_trash_post($test_post_id);
                    $warning_response = ['status' => 'ERROR', 'message' => 'Verification partially failed: Could not automatically delete test post. Please check trash.'];
                    $this->log_webhook_activity($endpoint, $method, $request->get_params(), $warning_response, 207, microtime(true) - $start_time, 'Could not delete test post', $test_post_id, 'warning');
                    return new WP_REST_Response($warning_response, 207);
                }

                update_option(self::IS_INTEGRATION_COMPLETED, true);
                $success_response = ['status' => 'SUCCESS', 'message' => 'AcmeBot integration verified successfully.'];
                $this->log_webhook_activity($endpoint, $method, $request->get_params(), $success_response, 200, microtime(true) - $start_time, null, $test_post_id);
                return new WP_REST_Response($success_response, 200);
            } catch (Exception $e) {
                $error_response = ['status' => 'ERROR', 'message' => 'Error during verification: ' . $e->getMessage()];
                $this->log_webhook_activity($endpoint, $method, $request->get_params(), $error_response, 500, microtime(true) - $start_time, $e->getMessage(), null, 'error');
                return new WP_REST_Response($error_response, 500);
            }
        }
    }

    /**
     * Initialize the plugin.
     * @return AcmeBot
     */
    function acmebot()
    {
        return AcmeBot::get_instance();
    }
    acmebot();
}
