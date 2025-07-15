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
$is_integration_completed = get_option(AcmeBot::IS_INTEGRATION_COMPLETED);
$is_connected = !empty($acmebot_secret);
$webhook_url = $is_connected ? rest_url('acmebot/v' . AcmeBot::REST_VERSION . '/webhook') : '';
$documentation_url = 'https://acme.bot/blog/application-passwords';

// Get any error messages that need to be displayed
$error_messages = get_transient('acmebot_settings_errors');
?>
<div class="acmebot-settings-wrap">
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
    endif; ?>

    <div class="acmebot-content-box">
        <div class="acmebot-card">
            <div class="acmebot-card-body">
                <?php if ($is_connected) : ?>
                    <div class="acmebot-logo-box">
                        <img src="<?php echo esc_url(AcmeBot::get_asset_url('images/logo-small-wide.svg')); ?>" alt="Acme Bot" class="acmebot-logo-img" loading="lazy" />
                    </div>

                    <h2 class="acmebot-card-title">Automate content marketing with ACME BOT</h2>
                    <?php if ($is_integration_completed) : ?>
                        <p>Acme Bot is successfully connected to this site.</p>
                    <?php endif; ?>

                    <?php if (!$is_integration_completed) : ?>
                        <p>Acme Bot connection is incomplete! Please try to reconnect.</p>
                    <?php endif; ?>

                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="acmebot-connect-form">
                        <input type="hidden" name="action" value="acmebot_handle_form">
                        <?php wp_nonce_field('acmebot_settings_action', 'acmebot_settings_nonce'); ?>
                        <div class="acmebot-items-center">
                            <?php submit_button('Reconnect to Acme Bot', 'primary large', 'submit', true); ?>
                        </div>
                    </form>
                    <p class="text-muted">If you need to refresh or update your connection, click "Reconnect".</p>

                <?php else : ?>
                    <div class="acmebot-logo-box">
                        <img src="<?php echo esc_url(AcmeBot::get_asset_url('images/logo-small-wide.svg')); ?>" alt="Acme Bot" class="acmebot-logo-img" loading="lazy" />
                    </div>

                    <h2 class="acmebot-card-title">Automate content marketing with ACME BOT</h2>
                    <p>Set up your Acme Bot account to enable AI features on this site.</p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="acmebot-connect-form">
                        <input type="hidden" name="action" value="acmebot_handle_form">
                        <?php wp_nonce_field('acmebot_settings_action', 'acmebot_settings_nonce'); ?>
                        <div class="acmebot-items-center">
                            <?php submit_button('Connect to Acme Bot', 'primary large', 'submit', true); ?>
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
                            'Alternatively, <a href="%s" target="_blank" rel="noopener noreferrer">learn about Application Passwords</a>.',
                            ['a' => ['href' => [], 'target' => [], 'rel' => []]]
                        ),
                        esc_url($documentation_url)
                    );
                    ?>
                </p>
                <p>
                    <small>Application Passwords might be required for alternative authentication methods. The primary connection method above is recommended.</small>
                </p>
            </div>
        <?php endif; ?>
    </div>
</div>