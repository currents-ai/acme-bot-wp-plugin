<?php

/**
 * Provide an admin area view for the plugin
 *
 * This file is used to markup the admin-facing aspects of the plugin.
 *
 * @link       https://acme.bot
 * @since      1.0.0
 *
 * @package    AcmeBot
 */

if (!defined('ABSPATH')) {
    exit;
}

$acmebot_secret = get_option(AcmeBot::SECRET_OPTION);
$is_connected = !empty($acmebot_secret);
$webhook_url = $is_connected ? rest_url('acmebot/v' . AcmeBot::REST_VERSION . '/webhook') : '';
$documentation_url = 'https://acme.bot/blog/application-passwords';
$logo_url = 'https://acme.bot/logo/logo-small-wide.svg';

// Get any error messages that need to be displayed
$error_messages = get_transient('acmebot_settings_errors');
$success_message = isset($_GET['acmebot_setup_success']) && $_GET['acmebot_setup_success'] === '1';
?>
<div class="settings-wrap">
    <h1 class="title"><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php
    // Display error messages if any
    if (!empty($error_messages) && is_array($error_messages)) : ?>
        <div class="acmebot-notice error-notice">
            <?php foreach ($error_messages as $error) : ?>
                <p><?php echo esc_html($error); ?></p>
            <?php endforeach; ?>
        </div>
    <?php
        // Clear the error messages after displaying them
        delete_transient('acmebot_settings_errors');
    endif;

    // Display success message if applicable
    if ($success_message) : ?>
        <div class="acmebot-notice success-notice is-dismissible">
            <p><?php esc_html_e('Acme Bot integration setup was successful!', 'acme-bot'); ?></p>
        </div>
    <?php endif; ?>

    <div class="content-box">
        <div class="card">
            <div class="card-body">
                <?php if ($is_connected) : ?>
                    <div class="logo-box">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Acme Bot" class="acmebot-logo-img" />
                    </div>

                    <h2 class="card-title"><?php esc_html_e('Connection Active', 'acme-bot'); ?></h2>
                    <p><?php esc_html_e('Acme Bot is successfully connected to this site.', 'acme-bot'); ?></p>

                    <!-- <?php if ($webhook_url) : ?>
                        <div class="acmebot-webhook-box">
                            <span class="acmebot-webhook-label"><?php esc_html_e('Your Webhook URL:', 'acme-bot'); ?></span>
                            <div class="acmebot-connected-content">
                                <code><?php echo esc_html($webhook_url); ?></code>
                            </div>
                        </div>
                    <?php endif; ?> -->

                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="acmebot-connect-form">
                        <input type="hidden" name="action" value="acmebot_handle_form">
                        <?php wp_nonce_field('acmebot_settings_action', 'acmebot_settings_nonce'); ?>
                        <div class="btn-center">
                            <?php submit_button(__('Reconnect to Acme Bot', 'acme-bot'), 'primary large btn', 'submit', true); ?>
                        </div>
                    </form>
                    <p class="text-muted"><?php esc_html_e('If you need to refresh or update your connection, click "Reconnect".', 'acme-bot'); ?></p>

                <?php else : ?>
                    <div class="logo-box">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Acme Bot" class="acmebot-logo-img" />
                    </div>

                    <h2 class="card-title"><?php esc_html_e('Connect to Acme Bot', 'acme-bot'); ?></h2>
                    <p><?php esc_html_e('Set up your Acme Bot account to enable AI features on this site.', 'acme-bot'); ?></p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="acmebot-connect-form">
                        <input type="hidden" name="action" value="acmebot_handle_form">
                        <?php wp_nonce_field('acmebot_settings_action', 'acmebot_settings_nonce'); ?>
                        <div class="btn-center">
                            <?php submit_button(__('Connect to Acme Bot', 'acme-bot'), 'primary large btn', 'submit', true); ?>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>

        <?php if (!$is_connected) : ?>
            <div class="acmebot-secondary-link">
                <p>
                    <?php
                    printf(
                        wp_kses(
                            __('Alternatively, <a href="%s" target="_blank" rel="noopener noreferrer">learn about Application Passwords</a>.', 'acme-bot'),
                            ['a' => ['href' => [], 'target' => [], 'rel' => []]]
                        ),
                        esc_url($documentation_url)
                    );
                    ?>
                </p>
                <p>
                    <small><?php esc_html_e('Application Passwords might be required for alternative authentication methods. The primary connection method above is recommended.', 'acme-bot'); ?></small>
                </p>
            </div>
        <?php endif; ?>
    </div>
</div>

<style>
    /* Main Settings Container */
    .settings-wrap {
        font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
        min-height: calc(100vh - 10rem);
        padding: 40px 20px 60px;
        margin-top: 20px;
    }

    /* Page Title */
    .title {
        text-align: center;
        font-size: 2.4em;
        font-weight: 700;
        margin: 20px 0 40px 0;
        letter-spacing: -1px;
        color: #1a2238;
        text-shadow: 0px 1px 2px rgba(255, 255, 255, 0.8);
        position: relative;
    }

    .title:after {
        content: "";
        display: block;
        width: 80px;
        height: 4px;
        background: linear-gradient(90deg, #2563eb 0%, #22d3ee 100%);
        margin: 15px auto 0;
        border-radius: 2px;
    }

    /* Content Container */
    .content-box {
        max-width: 520px;
        margin: 0 auto;
    }

    /* Card Design */
    .card {
        background: #fff;
        border-radius: 20px;
        box-shadow: 0 8px 30px rgba(30, 34, 90, 0.09), 0 2px 8px rgba(30, 34, 90, 0.05);
        padding: 0 0 40px 0;
        margin-bottom: 40px;
        border: none;
        transition: all 0.3s ease;
        overflow: hidden;
        position: relative;
    }

    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 40px rgba(30, 34, 90, 0.12), 0 4px 12px rgba(30, 34, 90, 0.08);
    }

    .card:before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 6px;
        background: linear-gradient(90deg, #2563eb 0%, #22d3ee 100%);
    }

    .card-body {
        padding: 45px 40px 0 40px;
        text-align: center;
    }

    /* Logo Styling */
    .logo-box {
        margin: 1.5rem auto 2.5rem;
        display: flex;
        justify-content: center;
        align-items: center;
        transition: transform 0.3s ease;
    }

    .logo-box:hover {
        transform: scale(1.05);
    }

    .acmebot-logo-img {
        width: fit-content;
        height: auto;
        display: block;
        margin: 0 auto;
        filter: drop-shadow(0 4px 6px rgba(30, 34, 90, 0.15));
    }

    /* Card Title */
    .card-title {
        font-size: 1.6em;
        font-weight: 700;
        margin: 0 0 22px 0;
        color: #1a2238;
        letter-spacing: -0.5px;
    }


    /* Webhook Box */
    .acmebot-webhook-box {
        background: linear-gradient(145deg, #f5f9ff 0%, #eef3fa 100%);
        border-radius: 12px;
        padding: 16px 20px;
        margin: 24px 0 16px 0;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        word-break: break-all;
        border: 1px solid rgba(37, 99, 235, 0.1);
    }

    .acmebot-webhook-label {
        font-size: 14px;
        color: #4b5d78;
        margin-bottom: 6px;
        font-weight: 600;
    }

    .acmebot-connected-content code {
        background: #e6edf7;
        color: #0f172a;
        border: none;
        border-radius: 6px;
        padding: 10px 14px;
        font-size: 14px;
        margin: 0;
        font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.05);
        width: 100%;
        display: block;
    }

    .text-muted {
        color: #64748b;
        font-size: 13px;
        margin-top: 12px;
        font-style: italic;
    }

    /* Form */
    .acmebot-connect-form {
        margin-top: 32px;
    }

    .btn-center {
        display: flex;
        justify-content: center;
        align-items: center;
    }

    /* Connect Button */
    .btn.button-primary.large {
        background: linear-gradient(90deg, #2563eb 0%, #22d3ee 100%);
        border: none;
        color: #fff;
        font-size: 1.15em;
        font-weight: 600;
        padding: 15px 36px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
        transition: all 0.3s ease;
        cursor: pointer;
        margin: 0 auto;
        display: block;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .btn.button-primary.large:hover,
    .btn.button-primary.large:focus {
        background: linear-gradient(90deg, #1e40af 0%, #06b6d4 100%);
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.35);
        transform: translateY(-2px);
    }

    .btn.button-primary.large:active {
        transform: translateY(1px);
        box-shadow: 0 2px 8px rgba(37, 99, 235, 0.2);
    }

    /* Secondary Link */
    .acmebot-secondary-link {
        background: #fff;
        border-radius: 16px;
        box-shadow: 0 3px 12px rgba(30, 34, 90, 0.06);
        padding: 22px 28px;
        text-align: center;
        font-size: 15px;
        color: #334155;
        border: 1px solid rgba(37, 99, 235, 0.06);
        transition: all 0.3s ease;
    }

    .acmebot-secondary-link:hover {
        box-shadow: 0 5px 15px rgba(30, 34, 90, 0.09);
        transform: translateY(-3px);
    }

    .acmebot-secondary-link a {
        color: #2563eb;
        text-decoration: none;
        font-weight: 600;
        transition: all 0.2s ease;
        border-bottom: 1px solid transparent;
        padding-bottom: 2px;
    }

    .acmebot-secondary-link a:hover {
        color: #0ea5e9;
        border-bottom: 1px solid #0ea5e9;
    }

    .acmebot-secondary-link small {
        color: #64748b;
        display: block;
        margin-top: 12px;
        font-style: italic;
    }

    .acmebot-notice {
        max-width: 520px;
        margin: 0 auto 30px;
        padding: 15px 20px;
        border-radius: 12px;
        box-shadow: 0 3px 10px rgba(0, 0, 0, 0.07);
        border-left: 4px solid;
        animation: fadeIn 0.4s ease-out forwards;
    }

    .acmebot-notice p {
        margin: 8px 0;
        font-size: 14px;
    }

    .acmebot-notice.error-notice {
        background-color: #fff5f5;
        border-left-color: #e53e3e;
        color: #c53030;
    }

    .acmebot-notice.success-notice {
        background-color: #f0fff4;
        border-left-color: #38a169;
        color: #2f855a;
    }

    /* Responsive */
    @media (max-width: 600px) {
        .title {
            font-size: 2em;
        }

        .content-box {
            max-width: 100%;
        }

        .card-body {
            padding: 30px 20px 0 20px;
        }

        .btn.button-primary.large {
            padding: 12px 24px;
            font-size: 1em;
            width: 100%;
        }

        .acmebot-secondary-link {
            padding: 18px 20px;
        }

        .acmebot-notice {
            max-width: 100%;
            margin-bottom: 20px;
        }
    }

    /* Animation Effects */
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }

        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .acmebot-settings-wrap {
        animation: fadeIn 0.5s ease-out forwards;
    }

    .card {
        animation: fadeIn 0.6s ease-out forwards;
        animation-delay: 0.1s;
    }

    .acmebot-secondary-link {
        animation: fadeIn 0.7s ease-out forwards;
        animation-delay: 0.2s;
    }
</style>