<?php
/*
Plugin Name:  CloudAware Security Audit
Plugin URI:   https://www.cloudaware.eu
Description:  Plugin to monitor and audit security aspects of your Wordpress installation
Version:      1.0.9
Author:       Jeroen Hermans
License:      GPLv2
Text Domain:  cloudaware-security-audit
*/

defined( 'ABSPATH' ) || die( 'No script kiddies please!' );
define("REQUESTHEADERS", array(
    'timeout' => 10,
    'User-Agent' => 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0'
));

function cloudseca_make_data() {
  global $wpdb;

  //This include is needed to get all updates for plugins in the same way as:
  //https://wordpress.org/plugins/wpvulnerability/
  if ( ! function_exists( 'get_plugin_updates' ) ) {
    require_once ABSPATH . 'wp-admin/includes/update.php';
  }
  $plugin_updates = get_plugin_updates();
  $theme_updates  = get_theme_updates();
  $core_updates   = (array)get_core_updates()["0"];

  //This include is needed to get all plugins installed on the system in the same way as:
  //https://wordpress.org/plugins/wpvulnerability/
  if ( ! function_exists( 'get_plugins' ) ) {
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
  }
  $plugins        = get_plugins();
  $themes         = wp_get_themes();

  //Global
  $global_theme_autoupdate  = wp_is_auto_update_enabled_for_type( "theme" );
  $global_plugin_autoupdate = wp_is_auto_update_enabled_for_type( "plugin" );

  //Per plugin
  $auto_update_plugins = (array) get_site_option( 'auto_update_plugins', array() );
  $auto_update_themes  = (array) get_site_option( 'auto_update_themes', array() );
  $auto_update_core    = array (
                  'auto_update_core_dev'   => get_site_option( 'auto_update_core_dev',   'enabled' ) === 'enabled',
                  'auto_update_core_minor' => get_site_option( 'auto_update_core_minor', 'enabled' ) === 'enabled',
                  'auto_update_core_major' => get_site_option( 'auto_update_core_major', 'unset'   ) === 'enabled',
                        );

  //Optionally include wpvulnerability in order to get data about vulnerabilities
  $wpvulnerabilities = array();
  if ( ! function_exists( 'wpvulnerability_plugin_get_vulnerabilities' ) ) {
    if (defined('WPVULNERABILITY_PLUGIN_PATH')) {
      $file_path = WPVULNERABILITY_PLUGIN_PATH . '/wpvulnerability-plugins.php';
      if ( file_exists($file_path) ) {
        require_once $file_path;
      }
    }
    $wpvulnerabilities = wpvulnerability_plugin_get_vulnerabilities();
  }

  $data = array('global_autoupdates' => array('themes' => $global_theme_autoupdate, 'plugins' => $global_plugin_autoupdate),
                'core'    => $core_updates,
                'plugins' => $plugins,
                'themes'  => array(),
                'url'     => get_option( 'siteurl' ),
                'time'    => time(),
                'config'  => cloudseca_get_config($plugins),
                'themehashes'  => hashFoldersInDirectory(ABSPATH, 'wp-content/themes'),
                'pluginhashes' => hashFoldersInDirectory(ABSPATH, 'wp-content/plugins')
          );

  foreach($data['plugins'] as $name => &$plugindata) {
    if( in_array($name, $auto_update_plugins) ) {
      $plugindata['Autoupdate'] = true;
    } else {
      $plugindata['Autoupdate'] = false;
    }
    $plugindata['Active'] = is_plugin_active($name);
    if( array_key_exists($name, $wpvulnerabilities) ) {
      $plugindata['vulnerabilities'] = $wpvulnerabilities[$name]['vulnerabilities'];
      $plugindata['vulnerable']      = $wpvulnerabilities[$name]['vulnerable'];
    }
    $args = array(
        'slug' => $plugindata['TextDomain'],
        'fields' => array(
            'banners'      => false,
            'contributors' => false,
            'ratings'      => false,
            'screenshots'  => false,
            'sections'     => false,
            'tags'         => false,
            'version'      => true,
            'versions'     => false,
        )
    );

    //This include is needed to get information about installed plugins on the system in the same way as:
    //https://wordpress.org/plugins/wpvulnerability/
    if ( ! function_exists( 'plugins_api' ) ) {
      require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
    }
    $call_api = plugins_api( 'plugin_information', $args );
    $plugindata['Active_installs'] = $call_api->active_installs;
    $plugindata['Added']           = gmdate('Y-m-d', strtotime($call_api->added) );
    $plugindata['Last_updated']    = gmdate('Y-m-d H:i', strtotime( $call_api->last_updated) );
    $plugindata['Num_ratings']     = $call_api->num_ratings;
    $plugindata['Rating']          = $call_api->rating;

    if($name == 'revslider/revslider.php') {
      $url = 'https://www.sliderrevolution.com/documentation/changelog/';
      $res = wp_remote_get($url, REQUESTHEADERS);
      $html = wp_remote_retrieve_body($res);
      $dom = new DOMDocument;
      $dom->loadHTML($html);

      $nodevalue = $dom->getElementById('the_real_post_content')->getElementsByTagName('li')->item(1)->nodeValue;
      $re = '/([^\s]+)\s\((.*)\)/m';
      preg_match_all($re, $nodevalue, $matches, PREG_SET_ORDER, 0);

      $plugindata['version_latest']      = $matches[0][1];
      $plugindata['version_latest_date'] = date_parse($matches[0][2]);
      $plugindata['version_latest_date'] = $plugindata['Version_latest_date']['year'].'-'.$plugindata['Version_latest_date']['month'].'-'.$plugindata['Version_latest_date']['day'];
    } else {
      if( array_key_exists($name, $plugin_updates) ) {
        $plugindata['version_latest'] = $plugin_updates[$name]->update->new_version;
      } else {
        $plugindata['version_latest'] = $plugindata['Version'];
      }
    }
  }

  $active_theme = wp_get_theme()->get_stylesheet();
  foreach($themes as $name => &$themedata) {
    $data['themes'][$name]['autoupdate'] = in_array($name, $auto_update_themes);
    $data['themes'][$name]['active'] = ($active_theme == $name);

    $themedetails                     = wp_get_theme($name);
    $data['themes'][$name]['Update']  = $themedata->update;
    $data['themes'][$name]['Name']    = $themedetails->get('Name');
    $data['themes'][$name]['version'] = $themedetails->get('version');

    if( array_key_exists($name, $theme_updates) ) {
      $data['themes'][$name]['version_latest'] = $theme_updates[$name]->update['new_version'];
    } else {
      $data['themes'][$name]['version_latest'] = $data['themes'][$name]['version'];
    }
  }
  $data['core']['autoupdate'] = $auto_update_core;

  try {
    $im = new Imagick();
    $tmp = $im->getVersion()['versionString'];

    $re = '/ImageMagick\s([^\s]+)\s.+https:\/\/imagemagick\.org/m';
    preg_match_all($re, $tmp, $matches, PREG_SET_ORDER, 0);
    $current_version = $matches[0][1];

    $url = 'https://api.github.com/repos/ImageMagick/ImageMagick/releases';
    $res = wp_remote_get($url, REQUESTHEADERS);
    $json = wp_remote_retrieve_body($res);

    $releases = json_decode($json, true);
    $latest_version = $releases[0]['name'];

    $data['imagemagick']['version']        = $current_version;
    $data['imagemagick']['version_latest'] = $latest_version;
  } catch(Exception $e) {}

  if( !array_key_exists('curl', $data) ) {
    $data['curl'] = array();
  }
  $data['curl']['version'] = curl_version()['version'];

  $url  = 'https://api.github.com/repos/curl/curl/releases';
  $res = wp_remote_get($url, REQUESTHEADERS);
  $json = wp_remote_retrieve_body($res);

  $obj  = json_decode($json, true);
  $data['curl']['version_latest'] = $obj[0]['name'];

  return $data;
}

//rest api endpoint function
function cloudseca_security_status (WP_REST_Request $request) {
  $data = cloudseca_make_data();
  return new WP_REST_Response( $data );
}

add_action( 'rest_api_init', function () {
  //register_rest_route( 'cloudaware/v1', '/test/(?P<naam>\d+)', array(
  register_rest_route( 'cloudaware/v1', '/security_status', array(
    'methods' => 'GET',
    'callback' => 'cloudseca_security_status',
     'permission_callback' => function () {
      return current_user_can( 'activate_plugins' );
    }
  ) );
} );


############################################################################
####### Admin menu
####### https://deliciousbrains.com/create-wordpress-plugin-settings-page/
############################################################################

add_action( 'admin_menu', 'cloudseca_menu' );

function cloudseca_menu() {
  add_options_page( 'CloudAware', 'CloudAware Security', 'manage_options', 'cloudseca-admin-menu', 'cloudseca_options' );
}

function cloudseca_options() {
  if ( !current_user_can( 'manage_options' ) )  {
    wp_die( 'You do not have sufficient permissions to access this page.' );
  }
  echo "<h2>".esc_html("Cloudaware Security Settings")."</h2>\n";
  echo "<form action=\"".esc_url("options.php")."\" method=\"post\">\n";
  settings_fields( 'cloudseca_plugin_options' );
  do_settings_sections( 'cloudseca_plugin' );
  #echo "<input name=\"submit\" class=\"button button-primary\" type=\"submit\" value=\"". esc_attr( 'Save' ). "\" />\n";
  submit_button('Save Settings');
  echo "</form>\n";

  echo "<button id=\"cloudseca_activate_btn\" class=\"button button-secondary\">Create role and user</button>\n";
  echo "<div id=\"cloudseca_modal\" style=\"display:none;\">\n";
  echo "  <p><span class=\"dashicons dashicons-warning\" style=\"color: #d63638; font-size: 18px; vertical-align: middle; margin-right: 6px;\"></span>\n";
  echo "  A new user <strong>cloudaware</strong> will be created with minimal access (role <code>cloudseca_api</code>).<br>\n";
  echo "  If a cloudaware.eu callback url has been defined, a secure application password will be generated and sent to CloudAware’s secure callback URL for monitoring. If the callback url is not in the cloudaware.eu domain, it will be shown to you once and not send anywhere else.</p>\n";
  echo "  <button id=\"cloudseca_confirm_btn\" class=\"button button-primary\" style=\"background-color: #28a745; border-color: #28a745;\">Confirm</button>\n";
  echo "  <button id=\"cloudseca_cancel_btn\" class=\"button\" style=\"background-color: #dc3545; border-color: #dc3545; color: white;\">Cancel</button>\n";
  echo "</div>\n";
  echo "<div id=\"cloudseca_response\"></div>\n";

  echo "<script>\n";
  echo "document.addEventListener('DOMContentLoaded', function () {\n";
  echo "    const activateBtn = document.getElementById('cloudseca_activate_btn');\n";
  echo "    const modal = document.getElementById('cloudseca_modal');\n";
  echo "    const confirmBtn = document.getElementById('cloudseca_confirm_btn');\n";
  echo "    const cancelBtn = document.getElementById('cloudseca_cancel_btn');\n";
  echo "    const response = document.getElementById('cloudseca_response');\n\n";

  echo "    activateBtn.addEventListener('click', function(e) {\n";
  echo "        e.preventDefault();\n";
  echo "        modal.style.display = 'block';\n";
  echo "    });\n\n";

  echo "    cancelBtn.addEventListener('click', function() {\n";
  echo "        modal.style.display = 'none';\n";
  echo "    });\n\n";

  echo "    confirmBtn.addEventListener('click', function() {\n";
  echo "        modal.style.display = 'none';\n";
  echo "        response.innerHTML = 'Activating...';\n";
  echo "        fetch(ajaxurl, {\n";
  echo "            method: 'POST',\n";
  echo "            headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n";
  echo "            body: 'action=cloudseca_activate_api_user&_wpnonce=".esc_js(wp_create_nonce("cloudseca_nonce")) ."'\n";
  echo "        })\n";
  echo "        .then(res => res.json())\n";
  echo "        .then(data => {\n";
  echo "            response.innerHTML = data.success ? '<strong>Success:</strong> ' + data.data.message : '<strong>Error:</strong> ' + data.data.message;\n";
  echo "        })\n";
  echo "        .catch(err => {\n";
  echo "            response.innerHTML = '<strong>Error:</strong> Could not connect.';\n";
  echo "        });\n";
  echo "    });\n";
  echo "});\n";
  echo "</script>\n";
}

function cloudseca_register_settings() {
    // phpcs:ignore PluginCheck.CodeAnalysis.SettingSanitization.register_settingDynamic
    register_setting( 'cloudseca_plugin_options', //settings group name
                      'cloudseca_plugin_options', //name of option
                      array(
                        'sanitize_callback' => 'cloudseca_plugin_options_validate'
                      )
                    );
    add_settings_section( 'callback_url_settings',          //id
                          'Callback Settings',              //title 
                          'cloudseca_plugin_section_text',  //text at top of section below title
                          'cloudseca_plugin'                //page
                        );

    add_settings_field( 'cloudseca_plugin_setting_callback_url', //id
                        'Callback URL',                          //title
                        'cloudseca_plugin_setting_callback_url', //callback
                        'cloudseca_plugin',                      //page
                        'callback_url_settings'                  //section
                      );
}
add_action( 'admin_init', 'cloudseca_register_settings' );
add_action('wp_ajax_cloudseca_activate_api_user', 'cloudseca_handle_api_user_creation');

function cloudseca_plugin_options_validate( $input ) {
    $newinput['callback_url'] = trim( $input['callback_url'] );
    #if ( ! preg_match( '/^[a-z0-9]{32}$/i', $newinput['api_key'] ) ) {
    #    $newinput['api_key'] = '';
    #}

    return $newinput;
}

function cloudseca_plugin_section_text() {
    echo '<p>Settings used for CloudAware security</p>';
}

function cloudseca_plugin_setting_callback_url() {
    $option = get_option( 'cloudseca_plugin_options' );
    echo "<input id='cloudseca_plugin_options' name='cloudseca_plugin_options[callback_url]' type='text' value='" .
           esc_attr( $option['callback_url'] ) . "' />";
}

//get_option('dbi_example_plugin_options')[api_key]

function cloudseca_handle_api_user_creation() {
    check_ajax_referer('cloudseca_nonce');

    $role_name  = 'cloudseca_api';
    $role_label = 'Cloudseca API';
    $username   = 'cloudaware';
    $email      = 'wordpresssecurity@cloudaware.eu';
    // The exact permissions this role should have
    $desired_perms = [
        'activate_plugins'        => true,
        'list_users'              => true,
        'read'                    => true,
        'switch_themes'           => true,
        'view_site_health_checks' => true,
    ];

    // 1. Create role if needed
    $roles = wp_roles();
    if (!$roles->is_role($role_name)) {
        // Role does not exist — create it
        add_role($role_name, $role_label, $desired_perms);
    } else {
        // Role exists — ensure it has only the desired capabilities
        $role = get_role($role_name);
        if ($role) {
            // First, remove all existing caps
            foreach ($role->capabilities as $cap => $value) {
                $role->remove_cap($cap);
            }

            // Then, add the desired capabilities
            foreach ($desired_perms as $perm => $value) {
                $role->add_cap($perm, $value);
            }
        }
    }

    // 2. Create user if needed
    $user_id = username_exists($username);
    if (!$user_id && !email_exists($email)) {
        $password = wp_generate_password(24, true);
        $user_id = wp_create_user($username, $password, $email);
        if (is_wp_error($user_id)) {
            wp_send_json_error(['message' => 'Failed to create user.']);
        }
        $user = get_user_by('id', $user_id);
        $user->set_role($role_name);
    } else {
        // User exists — check and update role if necessary
        $user = get_user_by('id', $user_id);
        if ($user && $user->role !== $role_name) {
            $user->set_role($role_name);
        }
    }

    if (!$user_id) {
        wp_send_json_error(['message' => 'User exists but could not retrieve ID.']);
    }

    // 3. Create application password
    if (!class_exists('WP_Application_Passwords')) {
        require_once ABSPATH . 'wp-includes/class-wp-application-passwords.php';
    }

    $app_exists = WP_Application_Passwords::application_name_exists_for_user($user_id, 'cloudaware');
    if (!$app_exists) {
        $app_pass = WP_Application_Passwords::create_new_application_password($user_id, ['name' => 'cloudaware']);
        if (is_wp_error($app_pass)) {
            wp_send_json_error(['message' => 'Failed to create application password.']);
        }

        // 4. Send app pass to callback URL
        $options = get_option('cloudseca_plugin_options');
        #$callback = get_option('cloudseca_plugin_options')['callback_url'];
        $callback = isset($options['callback_url']) ? trim($options['callback_url']) : '';
        #if (!$callback || !filter_var($callback, FILTER_VALIDATE_URL)) {
        #    wp_send_json_error(['message' => 'Invalid or missing callback URL.']);
        #}

        if ($callback && stripos($callback, 'cloudaware.eu') !== false && filter_var($callback, FILTER_VALIDATE_URL)) {
          $send = wp_remote_post($callback, [
              'headers' => ['Content-Type' => 'application/json; charset=utf-8'],
              'body' => json_encode([
                  'app_pass' => $app_pass[0],
                  'url'      => get_option('siteurl'),
              ]),
              'method'      => 'POST',
              'data_format' => 'body',
              'timeout'     => 10,
          ]);

          $code = wp_remote_retrieve_response_code($send);
          if ($code >= 200 && $code < 300) {
              wp_send_json_success(['message' => 'API user created and app password sent to CloudAware.']);
          } else {
              wp_send_json_error(['message' => 'App password created but failed to notify CloudAware.']);
          }
        } else {
            // Show password to user
            wp_send_json_success([
                'message' => 'API user created. Please copy the application password now — it will not be shown again: <code>'.$app_pass[0].'</code>'
            ]);        }
    } else {
        wp_send_json_success(['message' => 'Application password already exists.']);
    }
}

function cloudseca_get_config($plugins){
  global $wpdb;
  $config = array();

  #2FA
  $config['2fa_enabled'] = false;
  if (
    array_key_exists('wordfence/wordfence.php', $plugins) &&
    function_exists('is_plugin_active') &&
    is_plugin_active('wordfence/wordfence.php')
  ) { #Wordfence is installed
    // Define the roles to check
    $target_roles = ['administrator', 'contributor', 'editor'];

    // Get all defined roles
    if (!function_exists('get_editable_roles')) {
      // needed for get_editable_roles()
      require_once ABSPATH . 'wp-admin/includes/user.php';
    }
    $all_roles = get_editable_roles();

    // Filter roles that exist
    $existing_roles = array_filter($target_roles, function($role) use ($all_roles) {
      return array_key_exists($role, $all_roles);
    });

    if (!empty($existing_roles)) {
      // Prepare setting keys for those roles
      $setting_keys = array_map(function($role) {
        return "required-2fa-role.$role";
      }, $existing_roles);

      // Try to get cached results
      $cache_key = 'wordfence_2fa_roles_settings';
      $settings = wp_cache_get($cache_key, 'wordfence');
      if ($settings === false) {
        $placeholders = implode(', ', array_fill(0, count($setting_keys), '%s'));
        $table_name = $wpdb->prefix . 'wfls_settings';

        // Fetch settings in a single query
        $query = "SELECT name, value FROM esc_sql($table_name) WHERE name IN ($placeholders)";
        // This IS a prepared statement using splat notation
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery
        $results = $wpdb->get_results($wpdb->prepare($query, ...$setting_keys), OBJECT_K);
        // Cache the results
        $settings = [];
        foreach ($results as $row) {
          $settings[$row->name] = $row->value;
        }

        wp_cache_set($cache_key, $settings, 'wordfence', 300); // Cache for 5 minutes
      }

      $all_roles_have_2fa = true;
      foreach ($existing_roles as $role) {
        $key = "required-2fa-role.$role";
        if (!isset($settings[$key]) || intval($settings[$key]) <= 0) {
          $all_roles_have_2fa = false;
          break;
        }
      }

      if ($all_roles_have_2fa) {
        $config['2fa_enabled'] = true;
      }
    }
  }

  #Configuration 
  $config['admin_user_found'] = username_exists( 'admin' );
  $config['disallow_file_edit'] = defined('DISALLOW_FILE_EDIT');
  $config['debug'] = (defined('WP_DEBUG') && WP_DEBUG);
  $config['debug_log'] = (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG);
  $config['debug_display'] = defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY;
  $config['script_debug'] = defined('SCRIPT_DEBUG') && SCRIPT_DEBUG;
  $config['home_https'] = (defined('WP_HOME') && strpos(WP_HOME, 'https://') === 0) ;
  $config['siteurl_https'] = (defined('WP_SITEURL') && strpos(WP_SITEURL, 'https://') === 0);
  $config['force_ssl_admin'] = (defined('FORCE_SSL_ADMIN') && strpos(FORCE_SSL_ADMIN, 'https://') === 0);
  $config['autosave_interval'] = defined('AUTOSAVE_INTERVAL')?AUTOSAVE_INTERVAL:null;
  $config['post_revisions'] = defined('WP_POST_REVISIONS')?WP_POST_REVISIONS:null;
  $config['empty_trash_days'] = defined('EMPTY_TRASH_DAYS')?EMPTY_TRASH_DAYS:null;
  $config['memory_limit'] = defined('WP_MEMORY_LIMIT')?WP_MEMORY_LIMIT:null;

  $url = rtrim(get_option( 'siteurl' ), "/");
  $url .= '/xmlrpc.php';
  $res = wp_remote_get($url, REQUESTHEADERS);
  $config['xmlrpc_enabled'] = (wp_remote_retrieve_response_code($res) == 200);
  $config['table_prefix'] = $wpdb->prefix;

  return $config;
}

function getFolderHash($folderPath) {
    $fileHashes = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($folderPath, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $relativePath = str_replace('\\', '/', substr($file->getPathname(), strlen($folderPath)));
            $contentHash = md5_file($file->getPathname());
            $fileHashes[$relativePath] = $contentHash;
        }
    }

    // Sort by path to ensure consistent order
    ksort($fileHashes);

    // Combine all file hashes into a single string
    $combined = '';
    foreach ($fileHashes as $path => $hash) {
        $combined .= $path . ':' . $hash . "\n";
    }

    // Final folder-level hash
    return md5($combined);
}

function hashFoldersInDirectory($baseDir, $subPath) {
    $result = [];
    $fullPath = rtrim($baseDir, '/') . '/' . trim($subPath, '/');

    if (!is_dir($fullPath)) {
        return $result;
    }

    foreach (scandir($fullPath) as $item) {
        if ($item === '.' || $item === '..') continue;
        $itemPath = $fullPath . '/' . $item;
        if (is_dir($itemPath)) {
            $relative = $subPath . '/' . $item;
            $result[$relative] = getFolderHash($itemPath);
        }
    }

    return $result;
}


############################################################################
####### Cron job
####### https://blazzdev.com/scheduled-tasks-cron-wordpress-plugin-boilerplate/
############################################################################
add_action( 'cloudseca_cron_security_check', 'cloudseca_plugin_cron_daily' );
function cloudseca_plugin_cron_daily() {
  #only runs if user explicitly set a callback URL, will never run without user interaction
  if (get_option('cloudseca_plugin_options')['callback_url'] != '') {
    $res = wp_remote_post(get_option('cloudseca_plugin_options')['callback_url'], array(
        'headers'     => array('Content-Type' => 'application/json; charset=utf-8'),
        'body'        => json_encode(cloudseca_make_data()),
        'method'      => 'POST',
        'data_format' => 'body',
    ));
  }
}

#####Initialise
register_activation_hook( __FILE__, 'cloudseca_activate_plugin' );
function cloudseca_activate_plugin() { // runs on plugin activation
  if ( get_option( 'cloudseca_plugin_options' )                 === false ||
       get_option( 'cloudseca_plugin_options' )['callback_url'] === false ||
       get_option( 'cloudseca_plugin_options' )['callback_url'] ==  ''
  ) {
    add_option( 'cloudseca_plugin_options', array('callback_url' => '') );
  }
};

add_action('init', 'cloudseca_init_plugin');
function cloudseca_init_plugin() {
  if ( ! wp_next_scheduled( 'cloudseca_cron_security_check' ) ) {
    wp_schedule_event( time(), 'daily', 'cloudseca_cron_security_check' ); // cloudseca_cron_security_check is a hook
  }
}

#Deinitialise
register_deactivation_hook( __FILE__, 'cloudseca_deactivate_plugin' ); 
function cloudseca_deactivate_plugin() {
  $timestamp = wp_next_scheduled( 'cloudseca_cron_security_check' );
  wp_unschedule_event( $timestamp, 'cloudseca_cron_security_check' );
}

//Deinstall
register_uninstall_hook(__FILE__, 'cloudseca_plugin_uninstall');
function cloudseca_plugin_uninstall() {
    // Delete user
    $user = get_user_by('login', 'cloudaware');
    if ($user) {
        wp_delete_user($user->ID);
    }

    // Remove custom role
    remove_role('cloudseca_api');

    // Delete plugin options
    delete_option('cloudseca_plugin_options');
}
