<?php
/*
Plugin Name: WP Cognito UserLogin
Plugin URI: https://github.com/tjsteinhaus/wp-cognito-userlogin
Description: 
Author: Tyler Steinhaus
Version: 1.0
Author URI:  
*/

namespace WP_Cognito_UserLogin;

define( 'WP_COGNITO_USERLOGIN_PATH', dirname( __FILE__ ) );

// Composer Autoload
require WP_COGNITO_USERLOGIN_PATH . '/vendor/autoload.php';

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class WP_Cognito_UserLogin {

    /**
     * Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
     */
    private $awsclient;

    private $clientID;

    private $accessToken;

    private $refreshToken;

    private $idToken;

    private $userData;

    private $expiration;

    /**
     * Constructor
     */
    public function __construct() {

        // Turn on sessions for WordPress if it's not already
        add_action('init', function() {
            if( is_admin() ) {
                add_action( 'post_submitbox_misc_actions', array( $this, 'securePageCheckboxAction' ) );
				add_action( 'save_post', array( $this, 'securePageCheckboxActionPost' ) );
				add_action( 'admin_menu', function() {
					add_menu_page('Cognito Settings', 'Cognito Settings', 'administrator', __FILE__, array( $this, 'cognitoOptionsPage' ) );
				} );

				add_action( 'admin_init', array( $this, 'registerSettings' ) );
                return;
            }

            if(!session_id()) {
                session_start();
            }
            
			// Setup Cognito Connection
			if( $this->areOptionsSet() ) {
				$this->cognitoConnection();
				$this->getSessions();
				$this->parseIdToken();
				
				if( WP_DEBUG ) {
					echo '<pre>'.print_r( $_SESSION, true ).'</pre>';
					echo 'User Data <pre>'.print_r( $this->userData, true ). '</pre>';
					echo 'Client Id <pre>'.print_r( $this->clientID, true ). '</pre>';
					echo 'Refresh Token <pre>'.print_r( $this->refreshToken, true ). '</pre>';
					echo 'AccessToken <pre>'.print_r( $this->accessToken, true ). '</pre>';
					echo 'ID Token <pre>'.print_r( $this->idToken, true ). '</pre>';
				}

				$this->isExpired();            

				add_action( 'wp', array( $this, 'setupFrontend' ) );
			}
        }, 1);
    }

    /**
     * Cognito Connection Setup
     * 
     * @since 11/28/2018
     */
    private function cognitoConnection() {
        $this->awsclient = new CognitoIdentityProviderClient( [
            'version' => 'latest',
            'region' => get_option( 'aws_region' ),
            'app_client_id' => get_option( 'app_client_id' ),
            'user_pool_id' => get_option( 'aws_userpool_id' ),
            'credentials' => [
                'key' => get_option( 'aws_key_id' ),
                'secret' => get_option( 'aws_key_secret' ),
            ],
            'http' => [ 'verify' => false ]
        ] );
	}
	
	/**
	 * Options set?
	 */
	private function areOptionsSet() {
		$options = array(
			'session_url',
			'login_url',
			'app_client_id',
			'aws_key_id',
			'aws_key_secret',
			'aws_region',
			'aws_userpool_id'
		);

		foreach( $options as $option ) {
			if( get_option( $option ) == '' ) {
				return false;
			}
		}

		return true;
	}

    /**
     * Parse IdToken and set data
     * 
     * @since 11/28/2018
     */
    private function parseIdToken() {
        if( empty( $this->idToken ) ) {
            return false;
        }

        // Parse IdToken
        preg_match( '/^(.+)\.(.+)\.(.+)$/', $this->idToken, $matches );

        if( empty( $matches[2] ) ) {
            return false;
        }

        // Users Data is stored in the 2nd (3rd) array index
        $parsedUserData = json_decode( base64_decode( $matches[2] ) );

        $this->userData = $parsedUserData;
        $this->expiration = $this->userData->exp;
    }

    /**
     * Check if Expired, if so refresh token
     * 
     * @since 11/28/2018
     */
    private function isExpired() {
        $current_time = time();
    
        if( ( $this->expiration - $current_time ) >= 60 ) {
            return false;
        }

        $this->refreshToken();

        return true;
    }

    /**
     * Refresh Token and store the new ones
     * 
     * @since 11/28/2018
     */
    private function refreshToken() {
        if( empty( $this->refreshToken ) ) return;

        $refresh = $this->awsclient->initiateAuth( [
            'ClientId' => $this->client_id,
            'AuthFlow' => 'REFRESH_TOKEN',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $this->refreshToken
            ],
        ] );
        $refresh = $refresh->toArray();

        $this->accessToken = $refresh['AuthenticationResult']['AccessToken'];
        $this->idToken = $refresh['AuthenticationResult']['IdToken'];

        $this->setSessions();
    }

    /**
     * Get the sessions
     * 
     * @since 11/28/2018
     */
    private function getSessions() {
        if( isset( $_SESSION['cognitoAccessToken'] ) ) {
            $this->accessToken = $_SESSION['cognitoAccessToken'];
        }

        if( isset( $_SESSION['cognitoRefreshToken'] ) ) {
            $this->refreshToken = $_SESSION['cognitoRefreshToken'];
        }

        if( isset( $_SESSION['cognitoIdToken'] ) ) {
            $this->idToken = $_SESSION['cognitoIdToken'];
        }
    }

    /**
     * Set the sessions
     * 
     * @since 11/28/2018
     */
    private function setSessions() {
        if( !empty( $this->accessToken ) ) {            
            $_SESSION['cognitoAccessToken'] = $this->accessToken;
        }
        
        if( !empty( $this->refreshToken ) ) {
            $_SESSION['cognitoRefreshToken'] = $this->refreshToken;
        }

        if( !empty( $this->idToken ) ) {
            $_SESSION['cognitoIdToken'] = $this->idToken;
        }

        if( !empty( $this->clientID ) ) {
            $_SESSION['cognitoClientId'] = $this->clientID;
        }
    }

    /**
     * Delete the sessions
     * 
     * @since 11/28/2018
     */
    private function deleteSessions() {
        unset( $_SESSION['cognitoAccessToken'] );
        unset( $_SESSION['cognitoRefreshToken'] );
		unset( $_SESSION['cognitoIdToken'] );
		unset( $_SESSION['cognitoClientId'] );
    }

    /**
     * Is Logged In
     * 
     * @since 11/28/2018
     */
    private function isLoggedIn() {
        if( !empty( $this->accessToken ) && !empty( $this->refreshToken ) && !empty( $this->idToken ) && !empty( $this->clientID ) ) {
            $this->isExpired();

            return true;
        } else {
            return false;
        }
    }

    /**
     * Check Permissions
     * 
     * @since 11/28/2018
     * 
     * @param $permission (string) Permission you want to see if the user has access to
     */
    private function checkPermissions( $permission ) {
        $permissions = in_array( $permission, json_decode( $this->userData->permission ) );

        return $permissions;
    }

    /**
     * Has access to the page
     * 
     * @since 11/28/2018
     */
    private function hasAccessToPage() {
        global $post;
        $getSecurePage = get_post_meta( $post->ID, 'securePage', true );

        // Does securePage exists in meta data, if it does, is it a secure page
        if( ( is_page() || is_single() ) && metadata_exists( $post->post_type, $post->ID, 'securePage' ) && $getSecurePage ) {
            if( !$this->isLoggedIn() ) {
                return false;
            }
    
            if( !$this->checkPermissions( 'VIEW_RISK_MANAGEMENT' ) ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Setup the frontend of the website
     * 
     * @since 11/28/2018
     */
    public function setupFrontend() {
		$this->fetchCognitoSession();
        if( !$this->hasAccessToPage() ) {
            header( 'Location: ' . get_option( 'login_url' ) );
        }
	}
	
	/**
	 * Check for ?code= query string and fetch data
	 * 
	 * @since 11/28/2018
	 */
	private function fetchCognitoSession() {
		$code = esc_attr( $_REQUEST['code'] );
		
		if( !isset( $code ) ) {
			return false;
		}

		if( empty( $code ) ) {
			return false;
		}

		if( strlen( $code ) < 100 ) {
			return false;
		}

		if( !( $session_url = get_option( 'session_url' ) ) ) {
			return false;
		}
		
		$response = wp_remote_request( $session_url, [
			'method' => 'DELETE',
			'headers' => [
				'x-code' => $code
			]
		] );

		$body = json_decode( $response['body'] );
		$this->accessToken = $body->accessToken;
		$this->idToken = $body->idToken;
		$this->refreshToken = $body->refreshToken;

		$this->setSessions();

		$requestUri = str_replace( get_site_url(), '', $body->redirectUri );
		if( $requestUri == '' ) {
			$requestUri = '/';
		}

		header( "Location: " . $requestUri );
		exit();
	}

    /**
     * Adds a checkbox to the post_submitbox_misc_actions box
     * on the post new/edit screen.
     * 
     * Allows the user to choose if the user needs to be logged into to view the page.
     * 
     * @since 11/28/2018
     */
    public function securePageCheckboxAction( $post ) {
        $securePage = get_post_meta( $post->ID, 'securePage', true );
        ?>
        <div class="misc-pub-section securePageCheckboxAction">
            <label class="selectit"><input value="1" type="checkbox" name="securePage" id="in-category-1" <?php echo ( $securePage ) ? ' checked="checked"' : ''; ?>> Secure Page</label>
        </div>
        <?php
    }

    /**
     * Saves the data from the post_submitbox_misc_actions
     * 
     * @since 11/28/2018
     */
    public function securePageCheckboxActionPost( $post_id ) {
        $post_type = get_post_type($post_id);

        if( !in_array( $post_type, array( 'post', 'page' ) ) ) return;

        // If this is just a revision, don't send the email.
        if( wp_is_post_revision( $post_id ) ) return;

        update_post_meta( $post_id, 'securePage', $_POST['securePage'] );
	}
	
	/**
	 * Register settings for admin controls
	 * 
	 * @since 11/29/2018
	 */
	public function registerSettings() {
		register_setting( 'cognito-settings', 'session_url' );
		register_setting( 'cognito-settings', 'login_url' );
		register_setting( 'cognito-settings', 'app_client_id' );
		register_setting( 'cognito-settings', 'aws_key_id' );
		register_setting( 'cognito-settings', 'aws_key_secret' );
		register_setting( 'cognito-settings', 'aws_region' );
		register_setting( 'cognito-settings', 'aws_userpool_id' );
	}

	/**
	 * Cognito Options Page
	 * 
	 * @since 11/29/2018
	 */
	public function cognitoOptionsPage() {
		?>
		<div class="wrap">
			<h1>Cognito Settings</h1>
			<form method="POST" action="options.php">
				<?php settings_fields( 'cognito-settings' ); ?>
				<?php do_settings_sections( 'cognito-settings' ); ?>

				<table class="form-table">
					<tr valign="top">
						<th scope="row">Session Transfer URL</th>
						<td><input class="regular-text" type="text" name="session_url" value="<?php echo esc_attr( get_option('session_url') ); ?>" /></td>
					</tr>

					<tr valign="top">
						<th scope="row">Login Portal URL</th>
						<td><input class="regular-text" type="text" name="login_url" value="<?php echo esc_attr( get_option('login_url') ); ?>" /></td>
					</tr>
				</table>
				<hr />
				<table class="form-table">
					<tr valign="top">
						<th scope="row">App Client ID</th>
						<td><input class="regular-text" type="text" name="app_client_id" value="<?php echo esc_attr( get_option('app_client_id') ); ?>" /></td>
					</tr>
					<tr valign="top">
						<th scope="row">AWS Key ID (IAM)</th>
						<td><input class="regular-text" type="text" name="aws_key_id" value="<?php echo esc_attr( get_option('aws_key_id') ); ?>" /></td>
					</tr>
					<tr valign="top">
						<th scope="row">AWS Key Secret</th>
						<td><input class="regular-text" type="password" name="aws_key_secret" value="<?php echo esc_attr( get_option('aws_key_secret') ); ?>" /></td>
					</tr>
					<tr valign="top">
						<th scope="row">AWS Region</th>
						<td><input class="regular-text" type="text" name="aws_region" value="<?php echo esc_attr( get_option('aws_region') ); ?>" /></td>
					</tr>
					<tr valign="top">
						<th scope="row">Cognito User Pool</th>
						<td><input class="regular-text" type="text" name="aws_userpool_id" value="<?php echo esc_attr( get_option('aws_userpool_id') ); ?>" /></td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}
}

new WP_Cognito_UserLogin();
 