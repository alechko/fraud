<?php

/*
Plugin Name: Fraud
Description: Used to detect fraud paid traffic.
Version: 1.0
Author: Alex
*/

# init database table
register_activation_hook( __FILE__, 'fraud_init_db' );

# remove database
register_deactivation_hook( __FILE__, 'fraud_deactivate' );
register_deactivation_hook( __FILE__, 'fraud_remove_db' ); # uncomment to drop db on plugin deactivation
register_uninstall_hook( __FILE__, 'fraud_remove_db' );

# add admin menu
add_action('admin_menu', 'fraud_admin_menu');



# interception
add_action( 'wp', 'fraud_detect' );

function fraud_detect(){
	if (is_admin()) return;
	global $wpdb;
	$wpdb->fraud_log	= $wpdb->prefix . 'fraud_log';

	# print_r($_SERVER);
	# print_r($_COOKIE);
	$paid_visit = false;
	# try to check if user came from paid source
	# first, by cookie
	if (isset($_COOKIE['__utmz']) && strstr($_COOKIE['__utmz'], 'gclid')){
		$paid_visit = true;
	} 
	# if cookie not set, check where he came from and look for the adwords 'glcid' var in origin url
	elseif (strstr($_SERVER['HTTP_REFERER'], 'glcid')){
		$paid_visit = true;
	}

	### uncomment to log ony paid visits
	# if (!$paid_visit){
	# 	return false; # exit if not paid visit
	# }

	# ok, it's a paid visit, lets log it
	$date = $event['date'] = date('Y-m-d H:i:s',time());
	$ip = $event['ip'] = $_SERVER['REMOTE_ADDR'];


	$result = $wpdb->insert( $wpdb->fraud_log, array( 'date' => $date, 'ip' => $ip));

	$fraud_interval = get_option('fraud_interval');
	$history = date('Y-m-d H:i:s',strtotime("$interval -$fraud_interval minutes"));
	$count = $wpdb->get_results("SELECT COUNT(*) AS count FROM $wpdb->fraud_log WHERE date>'$history' AND ip='$ip'");
	if ($count[0]->count > 1) {
		# fraud_alert($event);
		echo "fr";

		$site = strstr(get_bloginfo('siteurl'),'https') ? substr(get_bloginfo('siteurl'), 8) : substr(get_bloginfo('siteurl'), 7);
		$content = 
		'<h3>Possible PPC Fraud on '.$site.' !</h3>'.
		'<p>The following IP visited the site more then twice in the last '.$fraud_interval.' minutes!</p>'
		;

		#TODO: get the list of emails from     $fraud_hash = json_decode( get_option('fraud_hash') );
		# wp_mail( get_option( 'admin_email' ), "[ " . get_option( 'blogname' ) . " ] ".__( 'Delete My Site' ), $content );
		$subject = __('possible at '.esc_attr($site).' ');
		wp_mail( 'mail@alechko.net', __($subject), $content );
		}

	# remove old records
	$fraud_ttl = get_option('fraud_ttl');
	$ttl = date('Y-m-d H:i:s',strtotime("now -$fraud_ttl days"));
	$wpdb->query("DELETE FROM $wpdb->fraud_log WHERE date<'$ttl'");
/*
	# for some reason, using add_action('init', 'fraud_detect'); calls this function multiple times
	# using count query and matching the current time we're preventing same record beign written twice into DB
	# it's important to use $date var to set the webserver date
	# search for same event in radius of 5 seconds
	$f = date('Y-m-d H:i:s',strtotime("$date -5 seconds"));
	$u = date('Y-m-d H:i:s',strtotime("$date +5 seconds"));
	# $count = $wpdb->get_results("SELECT COUNT(*) AS count FROM $wpdb->fraud_log WHERE date>'$f' AND date<'$u' AND ip='$ip'");
	# if ($count[0]->count < 1){
		# we've got no similar events logged, lets log this one
		fraud_write_log($event);
		# lets see if the ip is already logged within click interval
		fraud_count($event);
	# } 
*/
		return;
}


### admin options
function fraud_admin_menu() {
  if($_REQUEST['fraud_hidden']=="fraud_hidden"){
    $fraud_emails = $_REQUEST['fraud_emails'];
    $fraud_interval = $_REQUEST['fraud_interval'];
    $fraud_ttl = $_REQUEST['fraud_ttl'];
    $fraud_hash = array();
    foreach($fraud_emails as $key=>$email) {
      if($email) $fraud_hash[$key] = $email;
    }
    $fraud_hash = json_encode($fraud_hash);
    update_option('fraud_hash', $fraud_hash);
    update_option('fraud_interval', $fraud_interval);
    update_option('fraud_ttl', $fraud_ttl);
  }
  add_options_page('Fraud options', 'Fraud', 8, __FILE__, 'fraud_admin_options');
}

function fraud_admin_options(){
  if( get_option('fraud_hash') ){
    $fraud_hash = json_decode( get_option('fraud_hash') );
  } else {
    $fraud_hash[''] = '';
  }
  $fraud_interval = get_option('fraud_interval');
  $fraud_ttl = get_option('fraud_ttl');
	?>
	<style type="text/css">
	<!--
	a.remove_email:link, a.remove_email:visited { display: inline-block; padding: 2px 3px 3px; line-height: 11px; font-size: 11px; background: #888; color: #fff; font-family: "Comic Sans MS"; font-weight: bold; -moz-border-radius: 3px; border-radius: 3px; text-decoration: none;  }
	a.remove_email:hover { background: #BBB; }
	-->
	</style>j
	<form method="post" action="">
	  <h2>Fraud</h2>

	  General options:<br/>
	  <p><strong>Interval between clicks from same IP [minutes]</strong>
	  <input type="text" name="fraud_interval" value="<?php echo $fraud_interval;?>" size="8" autocomplete="off" />	
	  <p><strong>Time to live per IP [days]</strong>
	  <input type="text" name="fraud_ttl" value="<?php echo $fraud_ttl;?>" size="8" autocomplete="off" />	

	  <br/>List of emails for sending alert on possible fraud detection:<br/>

	  <?php if(count($fraud_hash) > 0): ?>
	  <?php foreach($fraud_hash as $key => $val): ?>
	  <p class="fraud_hash"><strong>Email</strong>
	  <input type="text" name="fraud_emails[]" value="<?php echo $val;?>" size="40" autocomplete="off" style="width: 280px" class="email_field" />
	  <a href="javascript:void(0)" class="remove_email">X</a></p>
	  <?php endforeach; ?>
	  <?php else: ?>
	  <p class="fraud_hash"><strong><?php echo $key; ?></strong>
	  <input type="text" name="fraud_emails[]" value="" size="40" autocomplete="off" />
	  <a href="javascript:void(0)" class="remove_email">x</a></p>
	  <?php endif; ?>
	<div>
	  <input type="hidden" name="fraud_hidden" value="fraud_hidden" />
	  <input type="button" id="add_another" value="Add more"/>
	  <input type="submit" value="Update"/>
	</div>
	</form>
	<script type="text/javascript">
	<!--
	jQuery(function(){
	  jQuery('#add_another').click(function(){
	    jQuery('.fraud_hash:last').after( jQuery('.fraud_hash:eq(0)').clone() );
	    jQuery('.fraud_hash:last').find('input').val("");
	  });
	  jQuery('.remove_email').live('click', function(){
	    if( jQuery('.fraud_hash').length > 1 )
	      jQuery(this).parents('.fraud_hash:first').remove();
	    else
	      alert('Cannot remove the last email');
	  });
	});
	-->
	</script>
	<?php
}

### db init
function fraud_init_db(){

	# init options
  update_option('fraud_interval', 120);	# interval 120 minutes
  update_option('fraud_ttl', 7);	# ttl 7 days
  $fraud_email = array(get_option('admin_email'));
  $fraud_hash = json_encode($fraud_email);
  update_option('fraud_hash', $fraud_hash); # first email, admin email by default

	global $wpdb;
	$wpdb->fraud_log	= $wpdb->prefix . 'fraud_log';

	if ( $wpdb->get_var("show tables like '$wpdb->fraud_log'") <> $wpdb->fraud_log ){
		$sql = "CREATE TABLE " . $wpdb->fraud_log . " (
				  id int(11) unsigned auto_increment,
				  ip varchar(15) default '',
				  date timestamp,
				  PRIMARY KEY  (id) ) ENGINE=MyISAM DEFAULT CHARSET=utf8;";
		require_once(ABSPATH . 'wp-admin/upgrade-functions.php');
		dbDelta($sql);
	  ###check
	  if( $wpdb->get_var("show tables like '$wpdb->fraud_log'") <> $wpdb->fraud_log ) {
	      ?>
	      <div id="message" class="updated fade">
	          <p><strong><?php echo sprintf(__('ERROR: fraud tracking table %s could not be created.', 'fraud'),'(<code>fraud_log</code>)') ?></strong></p>
	      </div>
	      <?php
	  update_option('cforms_settings',$cformsSettings);
	    }else{
	      ?>
	      <div id="message" class="updated fade">
	          <p><strong><?php echo sprintf(__('fraud tracking table %s have been created.', 'cforms'),'(<code>fraud_log</code>)') ?></strong></p>
	      </div>
	      <?php
	    	}
			}
		}

### remove db table
function fraud_remove_db(){
	# remove options
	delete_option( 'fraud_interval' ); 
	delete_option( 'fraud_ttl' ); 
	delete_option( 'fraud_hash' ); 
	global $wpdb;
	$wpdb->fraud_log	= $wpdb->prefix . 'fraud_log';	
	$wpdb->query("DROP TABLE IF EXISTS $wpdb->fraud_log");

}

function fraud_deactivate(){
	remove_action( 'send_headers', 'fraud_detect');
	remove_action( 'admin_menu', 'fraud_admin_menu');
}

?>