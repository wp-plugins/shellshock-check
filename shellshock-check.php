<?php

/*
 * Plugin Name: Shellshock Vulnerability Check
 * Description: Test if the server is affected by the Shellshock vulnerability.
 * Version: 1.1.0
 * Author: ManageWP
 * Author URI: https://managewp.com
 * License: GPL2
 */

if (!function_exists('add_action')) {
    exit;
}

function shell_shock_test_6271()
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        return false;
    }

    $env = array('SHELL_SHOCK_TEST' => '() { :;}; echo VULNERABLE');

    $desc = array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $p = proc_open('bash -c "echo Test"', $desc, $pipes, null, $env);
    $output = stream_get_contents($pipes[1]);
    proc_close($p);

    if (strpos($output, 'VULNERABLE') === false) {
        return false;
    }

    return true;
}

function shell_shock_test_7169()
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        return false;
    }

    $desc = array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $p = proc_open("rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir());
    $output = stream_get_contents($pipes[1]);
    proc_close($p);

    $test = date('Y');

    if (trim($output) === $test) {
        return true;
    }

    return false;
}

function shell_shock_test_menu()
{
    add_options_page('Shellshock Vulnerability Check', 'Shellshock', 'manage_options', 'shell-shock-test', 'shell_shock_test_page');
}

function shell_shock_test_page()
{
    // Dummy option, to hook to the WordPress API and enforce security when submitting the form.
    delete_option('shell_shock_test');
    $testPositive = null;
    $to = '';

    if (!empty($_GET['settings-updated']) && $_GET['settings-updated'] === 'true') {
        $testPositive = array();
        if (shell_shock_test_6271()) {
            $testPositive[] = '<a target="_blank" href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271">CVE-2014-6271</a>';
        }
        if (shell_shock_test_7169()) {
            $testPositive[] = '<a target="_blank" href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-7169">CVE-2014-7169</a>';
        }

        $to = implode(' and ', $testPositive);
    }

    ?>
    <div class="wrap">
        <h2>Shellshock Vulnerability Check
            <small>by <a target="_blank" href="https://managewp.com/">
                    ManageWP
                </a></small>
        </h2>

        <style scoped="scoped">
            #setting-error-settings_updated {
                display: none;
            }
        </style>

        <form method="post" action="options.php">
            <?php settings_fields('shell-shock-test'); ?>
            <?php do_settings_sections('shell-shock-test'); ?>

            <p>
                Shellshock is the code name for a security bug found in Bash shell, used on UNIX systems.
            </p>

            <p>
                The bug allows attacker to trick Bash into running a program that it wasn't supposed to. This has very
                serious security implications.
                <a target="_blank" href="https://managewp.com/shellshock-wordpress-check">Read more.</a>
            </p>

            <?php if (is_array($testPositive) && count($testPositive)): ?>
                <div class="error ">
                    <p>
                        <strong>Warning!</strong> The server appears to be vulnerable to <?=$to?>! Contact your server admin or
                        update your Bash.
                        <a target="_blank" href="https://managewp.com/shellshock-wordpress-check">Read more.</a>
                    </p>
                </div>
            <?php elseif (is_array($testPositive)): ?>
                <div class="updated ">
                    <p>
                        Congratulations, the server is not vulnerable.
                    </p>
                </div>
            <?php endif ?>

            <?php if (function_exists('proc_open')): ?>
                <?php submit_button("Run test"); ?>
            <?php else: ?>
                <div class="error">
                    <p>
                        You need the <code>proc_open</code> PHP function to run this test.
                    </p>
                </div>
            <?php endif ?>
        </form>

    </div>
<?php
}

function shell_shock_test_init()
{
    if (is_admin()) {
        register_setting('shell-shock-test', 'shell_shock_test');
    }
}

add_action('admin_menu', 'shell_shock_test_menu');
add_action('admin_init', 'shell_shock_test_init');
