<?php
/**
 * @author Amin Mahmoudi (MasterkinG)
 * @copyright    Copyright (c) 2019 - 2024, MasterkinG32. (https://masterking32.com)
 * @link    https://masterking32.com
 **/

use Gregwar\Captcha\CaptchaBuilder;

class user
{
    public static $captcha;

    public static function post_handler()
    {
        if (!empty($_GET['restore']) && !empty($_GET['key'])) {
            self::restorepassword_setnewpw($_GET['restore'], $_GET['key']);
        }

        if (!empty($_GET['enabletfa']) && !empty($_GET['account'])) {
            self::account_set_2fa($_GET['enabletfa'], $_GET['account']);
        }

        if (!empty($_POST['langchangever'])) {
            self::lang_cookie_changer($_POST['langchange']);
        }

        if (!empty($_POST['submit'])) {
            self::tfa_enable();
            if (get_config('battlenet_support')) {
                self::bnet_register();
                self::bnet_changepass();
            } else {
                self::normal_register();
                self::normal_changepass();
            }
            self::restorepassword();
            if (empty(get_config('captcha_type'))) {
                unset($_SESSION['captcha']);
                self::$captcha = new CaptchaBuilder;
                self::$captcha->build();
                $_SESSION['captcha'] = self::$captcha->getPhrase();
            }
        } else {
            if (empty(get_config('captcha_type'))) {
                unset($_SESSION['captcha']);
                self::$captcha = new CaptchaBuilder;
                self::$captcha->build();
                $_SESSION['captcha'] = self::$captcha->getPhrase();
            }
        }
    }

    /**
     * Language Changer
     */
    public static function lang_cookie_changer($getlang)
    {
        $supported_langs = get_config('supported_langs');
        if (!empty($supported_langs) && !empty($supported_langs[$getlang])) {
            setcookie('website_lang', $getlang);
            header("location: " . get_config("baseurl"));
            exit();
        }
    }

    /**
     * Battle.net registration (SRP6 only)
     */
    public static function bnet_register()
    {
        global $antiXss;
        if ($_POST['submit'] != 'register' || empty($_POST['password']) || empty($_POST['repassword']) || empty($_POST['email'])) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            error_msg(lang('use_valid_email'));
            return false;
        }

        if ($_POST['password'] != $_POST['repassword']) {
            error_msg(lang('passwords_not_equal'));
            return false;
        }

        if (get_config('srp6_support') && get_config('srp6_version') == 2) {
            if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 128)) {
                error_msg(lang('passwords_length'));
                return false;
            }
        } else {
            if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 16)) {
                error_msg(lang('passwords_length'));
                return false;
            }
        }

        if (!get_config('multiple_email_use') && !self::check_email_exists(strtoupper($_POST["email"]))) {
            error_msg(lang('username_or_email_exists'));
            return false;
        }

        if (empty(get_config('soap_for_register'))) {
            //Generate salt and verifier for Battle.net account
            if (get_config('srp6_version') == 2) {
                list($bnet_salt, $bnet_verifier) = getRegistrationDataBnetV2(strtoupper($_POST['email']), $_POST['password']);
            } else {
                list($bnet_salt, $bnet_verifier) = getRegistrationDataBnetV1(strtoupper($_POST['email']), $_POST['password']);
            }

            database::$auth->insert('battlenet_accounts', [
                'email' => $antiXss->xss_clean(strtoupper($_POST['email'])),
                'srp_version' => get_config('srp6_version'),
                'salt' => $bnet_salt,
                'verifier' => $bnet_verifier,
            ]);

            $bnet_account_id = database::$auth->lastInsertId();
            $game_account_name = $bnet_account_id . '#1';
            list($game_salt, $game_verifier) = getRegistrationData($game_account_name, $_POST['password']);

            database::$auth->insert('account', [
                'username' => $antiXss->xss_clean($game_account_name),
                'salt' => $game_salt,
                'verifier' => $game_verifier,
                'email' => $antiXss->xss_clean(strtoupper($_POST['email'])),
                'reg_mail' => $antiXss->xss_clean(strtoupper($_POST['email'])),
                'expansion' => $antiXss->xss_clean(get_config('expansion')),
                'battlenet_account' => $bnet_account_id,
                'battlenet_index' => 1,
            ]);

            success_msg(lang('account_created'));
            return true;
        } else {
            // SOAP method (not commonly used, but reserved)
            $command = str_replace('{USERNAME}', $antiXss->xss_clean($_POST['email']), get_config('soap_ca_command'));
            $command = str_replace('{PASSWORD}', $antiXss->xss_clean($_POST['password']), $command);
            if (RemoteCommandWithSOAP($command)) {
                success_msg(lang('account_created'));
            } else {
                error_msg(lang('error_try_again'));
            }
            return true;
        }
    }

    /**
     * Normal registration (non-Battle.net, SRP6 only)
     */
    public static function normal_register()
    {
        global $antiXss;
        if ($_POST['submit'] != 'register' || empty($_POST['password']) || empty($_POST['username']) || empty($_POST['repassword']) || empty($_POST['email'])) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        if (!preg_match('/^[0-9A-Z-_]+$/', strtoupper($_POST['username']))) {
            error_msg(lang('use_valid_username'));
            return false;
        }

        if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            error_msg(lang('use_valid_email'));
            return false;
        }

        if ($_POST['password'] != $_POST['repassword']) {
            error_msg(lang('passwords_not_equal'));
            return false;
        }

        if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 16)) {
            error_msg(lang('passwords_length'));
            return false;
        }

        if (!(strlen($_POST['username']) >= 2 && strlen($_POST['username']) <= 16)) {
            error_msg(lang('username_length'));
            return false;
        }

        if (!get_config('multiple_email_use') && !self::check_email_exists(strtoupper($_POST['email']))) {
            error_msg(lang('email_exists'));
            return false;
        }

        if (!self::check_username_exists(strtoupper($_POST['username']))) {
            error_msg(lang('username_exists'));
            return false;
        }

        list($salt, $verifier) = getRegistrationData(strtoupper($_POST['username']), $_POST['password']);

        if (empty(get_config('soap_for_register'))) {
            database::$auth->insert('account', [
                'username' => $antiXss->xss_clean(strtoupper($_POST['username'])),
                'salt' => $salt,
                'verifier' => $verifier,
                'email' => $antiXss->xss_clean(strtoupper($_POST['email'])),
                'reg_mail' => $antiXss->xss_clean(strtoupper($_POST['email'])),
                'expansion' => $antiXss->xss_clean(get_config('expansion')),
            ]);
            success_msg(lang('account_created'));
            return true;
        } else {
            $command = str_replace('{USERNAME}', $antiXss->xss_clean(strtoupper($_POST['username'])), get_config('soap_ca_command'));
            $command = str_replace('{PASSWORD}', $antiXss->xss_clean($_POST['password']), $command);
            $command = str_replace('{EMAIL}', $antiXss->xss_clean(strtoupper($_POST['email'])), $command);
            if (RemoteCommandWithSOAP($command)) {
                $queryBuilder = database::$auth->createQueryBuilder();
                $queryBuilder->update('account')
                    ->set('salt', ':salt')
                    ->set('verifier', ':verifier')
                    ->set('email', ':email')
                    ->where('username = :username')
                    ->setParameter('salt', $salt)
                    ->setParameter('verifier', $verifier)
                    ->setParameter('email', $antiXss->xss_clean(strtoupper($_POST['email'])))
                    ->setParameter('username', $antiXss->xss_clean(strtoupper($_POST['username'])));
                $queryBuilder->executeQuery();

                if (!empty(get_config('soap_asa_command'))) {
                    $command_addon = str_replace('{USERNAME}', $antiXss->xss_clean(strtoupper($_POST['username'])), get_config('soap_asa_command'));
                    $command_addon = str_replace('{EXPANSION}', get_config('expansion'), $command_addon);
                    RemoteCommandWithSOAP($command_addon);
                }
                success_msg(lang('account_created'));
            } else {
                error_msg(lang('error_try_again'));
            }
            return true;
        }
    }

    /**
     * Change password for Battle.net Cores (SRP6 only)
     */
    public static function bnet_changepass()
    {
        global $antiXss;

        if (!empty(get_config('disable_changepassword'))) {
            return false;
        }

        if ($_POST['submit'] != 'changepass' || empty($_POST['password']) || empty($_POST['old_password']) || empty($_POST['repassword']) || empty($_POST['email'])) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            error_msg(lang('use_valid_email'));
            return false;
        }

        if ($_POST['password'] != $_POST['repassword']) {
            error_msg(lang('passwords_not_equal'));
            return false;
        }

        if (get_config('srp6_support') && get_config('srp6_version') == 2) {
            if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 128)) {
                error_msg(lang('passwords_length'));
                return false;
            }
        } else {
            if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 16)) {
                error_msg(lang('passwords_length'));
                return false;
            }
        }

        $bnetAccountInfo = self::get_bnetaccount_by_email(strtoupper($_POST['email']));
        if (empty($bnetAccountInfo['email'])) {
            error_msg(lang('email_not_correct'));
            return false;
        }

        // Verify old password (based on version)
        $valid = false;
        if (get_config('srp6_version') == 2) {
            $valid = verifySRP6BnetV2($bnetAccountInfo['email'], $_POST['old_password'], $bnetAccountInfo['salt'], $bnetAccountInfo['verifier']);
        } else {
            $valid = verifySRP6BnetV1($bnetAccountInfo['email'], $_POST['old_password'], $bnetAccountInfo['salt'], $bnetAccountInfo['verifier']);
        }

        if (!$valid) {
            error_msg(lang('old_password_not_valid'));
            return false;
        }

        // Update Battlenet_comounts password
        if (get_config('srp6_version') == 2) {
            list($new_bnet_salt, $new_bnet_verifier) = getRegistrationDataBnetV2(strtoupper($bnetAccountInfo['email']), $_POST['password']);
        } else {
            list($new_bnet_salt, $new_bnet_verifier) = getRegistrationDataBnetV1(strtoupper($bnetAccountInfo['email']), $_POST['password']);
        }

        $queryBuilder = database::$auth->createQueryBuilder();
        $queryBuilder->update('battlenet_accounts')
            ->set('salt', ':salt')
            ->set('verifier', ':verifier')
            ->where('id = :id')
            ->setParameter('salt', $new_bnet_salt)
            ->setParameter('verifier', $new_bnet_verifier)
            ->setParameter('id', $bnetAccountInfo['id']);
        $queryBuilder->executeQuery();

        // Update associated game accounts (account table)
        $userinfo = self::get_user_by_email(strtoupper($_POST['email']));
        if (!empty($userinfo['id'])) {
            $game_username = $userinfo['username'];
            list($new_game_salt, $new_game_verifier) = getRegistrationData($game_username, $_POST['password']);
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->update('account')
                ->set('salt', ':salt')
                ->set('verifier', ':verifier')
                ->where('id = :id')
                ->setParameter('salt', $new_game_salt)
                ->setParameter('verifier', $new_game_verifier)
                ->setParameter('id', $userinfo['id']);
            $queryBuilder->executeQuery();
        }

        success_msg(lang('password_changed'));
        return true;
    }

    /**
     * Change password for normal servers (non-Battle.net, SRP6 only)
     */
    public static function normal_changepass()
    {
        global $antiXss;

        if (!empty(get_config('disable_changepassword'))) {
            return false;
        }

        if ($_POST['submit'] != 'changepass' || empty($_POST['password']) || empty($_POST['old_password']) || empty($_POST['repassword']) || empty($_POST['username'])) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        if ($_POST['password'] != $_POST['repassword']) {
            error_msg(lang('passwords_not_equal'));
            return false;
        }

        if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 16)) {
            error_msg(lang('passwords_length'));
            return false;
        }

        $userinfo = self::get_user_by_username(strtoupper($_POST['username']));
        if (empty($userinfo['username'])) {
            error_msg(lang('username_not_correct'));
            return false;
        }

        if (!verifySRP6($userinfo['username'], $_POST['old_password'], $userinfo['salt'], $userinfo['verifier'])) {
            error_msg(lang('old_password_not_valid'));
            return false;
        }

        list($new_salt, $new_verifier) = getRegistrationData(strtoupper($userinfo['username']), $_POST['password']);

        $queryBuilder = database::$auth->createQueryBuilder();
        $queryBuilder->update('account')
            ->set('salt', ':salt')
            ->set('verifier', ':verifier')
            ->where('id = :id')
            ->setParameter('salt', $new_salt)
            ->setParameter('verifier', $new_verifier)
            ->setParameter('id', $userinfo['id']);
        $queryBuilder->executeQuery();

        success_msg(lang('password_changed'));
        return true;
    }

    /**
     * Find Password - Send Reset Email
     */
    public static function restorepassword()
    {
        global $antiXss;
        if ($_POST['submit'] != 'restorepassword') {
            return false;
        }

        if (get_config('battlenet_support') && empty($_POST['email'])) {
            return false;
        } elseif (!get_config('battlenet_support') && empty($_POST['username'])) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        if (get_config('battlenet_support')) {
            if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
                error_msg(lang('use_valid_email'));
                return false;
            }
            $userinfo = self::get_user_by_email(strtoupper($_POST['email']));
            if (empty($userinfo['email'])) {
                error_msg(lang('email_not_correct'));
                return false;
            }
            $field_acc = $userinfo['email'];
        } else {
            if (!preg_match('/^[0-9A-Z-_]+$/', strtoupper($_POST['username']))) {
                error_msg(lang('use_valid_username'));
                return false;
            }
            $userinfo = self::get_user_by_username(strtoupper($_POST['username']));
            if (empty($userinfo['email'])) {
                error_msg(lang('username_not_correct'));
                return false;
            }
            $field_acc = $userinfo['username'];
        }

        if (!isset($userinfo['restore_key'])) {
            self::add_password_key_to_acctbl();
        }

        $restore_key = strtolower(md5(time() . mt_rand(1000, 9999)) . mt_rand(10000, 99999));

        $queryBuilder = database::$auth->createQueryBuilder();
        $queryBuilder->update('account')
            ->set('restore_key', ':restore_key')
            ->where('id = :id')
            ->setParameter('restore_key', $antiXss->xss_clean($restore_key))
            ->setParameter('id', $userinfo['id']);
        $queryBuilder->executeQuery();

        $restorepass_URL = get_config('baseurl') . '/index.php?restore=' . strtolower($field_acc) . '&key=' . $restore_key;
        $message = "Click on the following link to reset your game password：<br><a href='$restorepass_URL' target='_blank'>$restorepass_URL</a>";
        send_phpmailer(strtolower($userinfo['email']), lang('restore_account_password'), $message);
        success_msg(lang('check_your_email'));
        return true;
    }

    /**
     * Reset Password - Display Form through Key or Process New Password
     */
    public static function restorepassword_setnewpw($user_data, $restore_key)
    {
        global $antiXss;

        // Basic verification
        if (empty($user_data) || empty($restore_key)) {
            return false;
        }
        if ($restore_key == 1 || strlen($restore_key) < 30) {
            return false;
        }

        //Obtain user information
        if (get_config('battlenet_support')) {
            if (!filter_var($user_data, FILTER_VALIDATE_EMAIL)) {
                return false;
            }
            $userinfo = self::get_user_by_email(strtoupper($user_data));
        } else {
            if (!preg_match('/^[0-9A-Z-_]+$/', strtoupper($user_data))) {
                error_msg(lang('use_valid_username'));
                return false;
            }
            $userinfo = self::get_user_by_username(strtoupper($user_data));
        }

        if (empty($userinfo['email'])) {
            return false;
        }

        // Verify if the key matches
        if ($userinfo['restore_key'] != $restore_key) {
            return false;
        }

        // ========== GET request: Display password reset form ==========
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            // Output a complete HTML page
            ?>
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset password - <?php echo get_config('page_title'); ?></title>
                <link href="<?php echo get_config('baseurl'); ?>/template/<?php echo get_config('template'); ?>/assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
                <link href="<?php echo get_config('baseurl'); ?>/template/<?php echo get_config('template'); ?>/assets/css/style.css" rel="stylesheet">
                <style>
                    body { background: #f4f4f4; font-family: "Open Sans", sans-serif; }
                    .reset-container { max-width: 500px; margin: 80px auto; padding: 30px; background: #fff; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
                    .reset-container h2 { color: #333; text-align: center; margin-bottom: 25px; }
                    .btn-reset { background: #7cc576; color: #fff; border: none; padding: 10px 20px; width: 100%; }
                    .btn-reset:hover { background: #5ab652; }
                    .error-msg { color: #dc3545; margin-top: 10px; }
                    .success-msg { color: #28a745; margin-top: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="reset-container">
                        <h2>🔑 Reset password</h2>
                        <form method="post" action="<?php echo get_config('baseurl'); ?>/index.php?restore=<?php echo urlencode($user_data); ?>&key=<?php echo urlencode($restore_key); ?>">
                            <input type="hidden" name="restore" value="<?php echo htmlspecialchars($user_data); ?>">
                            <input type="hidden" name="key" value="<?php echo htmlspecialchars($restore_key); ?>">
                            <div class="form-group">
                                <label for="new_password">New password</label>
                                <input type="password" class="form-control" id="new_password" name="new_password" required minlength="4" maxlength="16" placeholder="Enter new password">
                            </div>
                            <div class="form-group">
                                <label for="confirm_password">Confirm Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="4" maxlength="16" placeholder="Enter new password again">
                            </div>
                            <button type="submit" class="btn btn-reset">Reset password</button>
                            <?php if (!empty($GLOBALS['error_msg'])): ?>
                                <div class="error-msg"><?php echo $GLOBALS['error_msg']; ?></div>
                            <?php endif; ?>
                            <?php if (!empty($GLOBALS['success_msg'])): ?>
                                <div class="success-msg"><?php echo $GLOBALS['success_msg']; ?></div>
                            <?php endif; ?>
                        </form>
                        <p class="text-center" style="margin-top: 20px;"><a href="<?php echo get_config('baseurl'); ?>" style="color: #7cc576;">Return to Home</a></p>
                    </div>
                </div>
            </body>
            </html>
            <?php
            exit; // Stop execution, do not load main.php
        }

        // ========== POST request: Process the submitted new password ==========
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Verify whether the submitted restore and key are consistent with the parameters
            if (empty($_POST['restore']) || empty($_POST['key']) || $_POST['restore'] != $user_data || $_POST['key'] != $restore_key) {
                $GLOBALS['error_msg'] = 'Invalid request';
                header('Location: ' . get_config('baseurl') . '/index.php?restore=' . urlencode($user_data) . '&key=' . urlencode($restore_key) . '&error=1');
                exit;
            }

            $new_password = $_POST['new_password'];
            $confirm = $_POST['confirm_password'];

            if (empty($new_password) || empty($confirm)) {
                $GLOBALS['error_msg'] = 'Please fill in all fields';
                header('Location: ' . get_config('baseurl') . '/index.php?restore=' . urlencode($user_data) . '&key=' . urlencode($restore_key) . '&error=1');
                exit;
            }

            if ($new_password !== $confirm) {
                $GLOBALS['error_msg'] = 'The passwords entered twice are inconsistent';
                header('Location: ' . get_config('baseurl') . '/index.php?restore=' . urlencode($user_data) . '&key=' . urlencode($restore_key) . '&error=1');
                exit;
            }

            //Password length limit (consistent with registration)
            if (get_config('srp6_support') && get_config('srp6_version') == 2) {
                if (!(strlen($new_password) >= 4 && strlen($new_password) <= 128)) {
                    $GLOBALS['error_msg'] = 'The password length must be between 4-128 bits';
                    header('Location: ' . get_config('baseurl') . '/index.php?restore=' . urlencode($user_data) . '&key=' . urlencode($restore_key) . '&error=1');
                    exit;
                }
            } else {
                if (!(strlen($new_password) >= 4 && strlen($new_password) <= 16)) {
                    $GLOBALS['error_msg'] = 'The password length must be between 4-16 digits';
                    header('Location: ' . get_config('baseurl') . '/index.php?restore=' . urlencode($user_data) . '&key=' . urlencode($restore_key) . '&error=1');
                    exit;
                }
            }

            // ----------Update password（SRP6） ----------
            if (get_config('battlenet_support')) {
                // 更新 battlenet_accounts
                if (get_config('srp6_version') == 2) {
                    list($bnet_salt, $bnet_verifier) = getRegistrationDataBnetV2(strtoupper($userinfo['email']), $new_password);
                } else {
                    list($bnet_salt, $bnet_verifier) = getRegistrationDataBnetV1(strtoupper($userinfo['email']), $new_password);
                }

                $queryBuilder = database::$auth->createQueryBuilder();
                $queryBuilder->update('battlenet_accounts')
                    ->set('salt', ':salt')
                    ->set('verifier', ':verifier')
                    ->where('id = :id')
                    ->setParameter('salt', $bnet_salt)
                    ->setParameter('verifier', $bnet_verifier)
                    ->setParameter('id', $userinfo['battlenet_account']);
                $queryBuilder->executeQuery();

                // Update account table (game accounts)
                $game_username = $userinfo['username'];
                list($game_salt, $game_verifier) = getRegistrationData($game_username, $new_password);

                $queryBuilder = database::$auth->createQueryBuilder();
                $queryBuilder->update('account')
                    ->set('salt', ':salt')
                    ->set('verifier', ':verifier')
                    ->set('restore_key', '1')
                    ->where('id = :id')
                    ->setParameter('salt', $game_salt)
                    ->setParameter('verifier', $game_verifier)
                    ->setParameter('id', $userinfo['id']);
                $queryBuilder->executeQuery();
            } else {
                // Not Battle.net
                list($salt, $verifier) = getRegistrationData(strtoupper($userinfo['username']), $new_password);

                $queryBuilder = database::$auth->createQueryBuilder();
                $queryBuilder->update('account')
                    ->set('salt', ':salt')
                    ->set('verifier', ':verifier')
                    ->set('restore_key', '1')
                    ->where('id = :id')
                    ->setParameter('salt', $salt)
                    ->setParameter('verifier', $verifier)
                    ->setParameter('id', $userinfo['id']);
                $queryBuilder->executeQuery();
            }

            // Success, redirect to the homepage with a success flag
            header('Location: ' . get_config('baseurl') . '/index.php?reset_success=1');
            exit;
        }

        return true;
    }

    // ---------- Auxiliary query function----------
    public static function check_email_exists($email)
    {
        if (!empty($email)) {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('id')
                ->from('account')
                ->where('email = :email')
                ->setParameter('email', strtoupper($email));
            $statement = $queryBuilder->executeQuery();
            $datas = $statement->fetchAllAssociative();
            if (empty($datas[0])) {
                return true;
            }
        }
        return false;
    }

    public static function get_user_by_email($email)
    {
        if (!empty($email)) {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('*')
                ->from('account')
                ->where('email = :email')
                ->setParameter('email', strtoupper($email));
            $statement = $queryBuilder->executeQuery();
            $datas = $statement->fetchAllAssociative();
            if (!empty($datas[0]['username'])) {
                return $datas[0];
            }
        }
        return false;
    }

    public static function get_bnetaccount_by_email($email)
    {
        if (!empty($email)) {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('*')
                ->from('battlenet_accounts')
                ->where('email = :email')
                ->setParameter('email', strtoupper($email));
            $statement = $queryBuilder->executeQuery();
            $datas = $statement->fetchAllAssociative();
            if (!empty($datas[0]['email'])) {
                return $datas[0];
            }
        }
        return false;
    }

    public static function get_user_by_username($username)
    {
        if (!empty($username)) {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('*')
                ->from('account')
                ->where('username = :username')
                ->setParameter('username', strtoupper($username));
            $statement = $queryBuilder->executeQuery();
            $datas = $statement->fetchAllAssociative();
            if (!empty($datas[0]['username'])) {
                return $datas[0];
            }
        }
        return false;
    }

    public static function check_username_exists($username)
    {
        if (!empty($username)) {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('id')
                ->from('account')
                ->where('username = :username')
                ->setParameter('username', strtoupper($username));
            $statement = $queryBuilder->executeQuery();
            $datas = $statement->fetchAllAssociative();
            if (empty($datas[0])) {
                return true;
            }
        }
        return false;
    }

    public static function get_online_players($realmID)
    {
        $queryBuilder = database::$chars[$realmID]->createQueryBuilder();
        $queryBuilder->select('name, race, class, gender, level')
            ->from('characters')
            ->where('online = :online')
            ->orderBy('level', 'DESC')
            ->setMaxResults(49)
            ->setParameter('online', 1);
        $statement = $queryBuilder->executeQuery();
        $datas = $statement->fetchAllAssociative();
        if (!empty($datas[0]['name'])) {
            return $datas;
        }
        return false;
    }

    public static function get_online_players_count($realmID)
    {
        $queryBuilder = database::$chars[$realmID]->createQueryBuilder();
        $queryBuilder->select('COUNT(*)')
            ->from('characters')
            ->where('online = :online')
            ->setParameter('online', 1);
        $statement = $queryBuilder->executeQuery();
        $datas = $statement->fetchOne();
        if (!empty($datas)) {
            return $datas;
        }
        return 0;
    }

    public static function add_password_key_to_acctbl()
    {
        try {
            $queryBuilder = database::$auth->createQueryBuilder();
            $queryBuilder->select('COLUMN_NAME')
                ->from('information_schema.COLUMNS')
                ->where('TABLE_SCHEMA = :db')
                ->andWhere('TABLE_NAME = :table')
                ->andWhere('COLUMN_NAME = :col')
                ->setParameter('db', get_config('db_auth_dbname'))
                ->setParameter('table', 'account')
                ->setParameter('col', 'restore_key');
            $result = $queryBuilder->executeQuery()->fetchOne();
            if (!$result) {
                database::$auth->executeQuery("ALTER TABLE `account` ADD COLUMN `restore_key` varchar(255) NULL DEFAULT '1';");
            }
        } catch (Exception $e) {
            // 忽略错误
        }
        return true;
    }

    /**
     * 2FA功能
     */
    public static function tfa_enable()
    {
        global $antiXss;

        if (empty(get_config('2fa_support'))) {
            return false;
        }

        if (empty($_POST['submit']) || $_POST['submit'] != 'etfa' || empty($_POST['email']) || (empty(get_config('battlenet_support')) && empty($_POST['username']))) {
            return false;
        }

        if (!captcha_validation()) {
            return false;
        }

        $userinfo = self::get_user_by_email(strtoupper($_POST['email']));
        if (empty($userinfo['id'])) {
            error_msg(lang('account_is_not_valid'));
            return false;
        }

        if (empty(get_config('battlenet_support')) && strtolower($userinfo['username']) != strtolower($_POST['username'])) {
            error_msg(lang('account_is_not_valid'));
            return false;
        }

        $verify_key = md5(strtolower($userinfo['email']) . "_" . time() . rand(1, 999999));

        if (!isset($userinfo['restore_key'])) {
            self::add_password_key_to_acctbl();
        }

        $queryBuilder = database::$auth->createQueryBuilder();
        $queryBuilder->update('account')
            ->set('restore_key', ':restore_key')
            ->where('id = :id')
            ->setParameter('restore_key', $antiXss->xss_clean($verify_key))
            ->setParameter('id', $userinfo['id']);
        $queryBuilder->executeQuery();

        $account = $userinfo['email'];
        if (empty(get_config('battlenet_support'))) {
            $account = $userinfo['username'];
        }

        $restorepass_URL = get_config('baseurl') . '/index.php?enabletfa=' . strtolower($verify_key) . '&account=' . strtolower($account);
        $message = "Click on the following link to enable two-step verification（2FA）：<br><a href='$restorepass_URL' target='_blank'>$restorepass_URL</a>";
        send_phpmailer(strtolower($userinfo['email']), 'Enable Account 2FA', $message);
        success_msg(lang('check_your_email'));
        return true;
    }

    public static function account_set_2fa($verify_key, $account)
    {
        global $antiXss;

        if (empty(get_config('2fa_support'))) {
            return false;
        }

        if (empty($verify_key) || empty($account)) {
            return false;
        }

        if ($verify_key == 1 || strlen($verify_key) < 30) {
            return false;
        }

        $acc_name = "";
        if (get_config('battlenet_support')) {
            if (!filter_var($account, FILTER_VALIDATE_EMAIL)) {
                return false;
            }
            $userinfo = self::get_user_by_email(strtoupper($account));
            $acc_name = $userinfo['email'];
        } else {
            if (!preg_match('/^[0-9A-Z-_]+$/', strtoupper($account))) {
                return false;
            }
            $userinfo = self::get_user_by_username(strtoupper($account));
            $acc_name = $userinfo['username'];
        }

        if (empty($userinfo['email'])) {
            return false;
        }

        if ($userinfo['restore_key'] != $verify_key) {
            return false;
        }

        $ga = new PHPGangsta_GoogleAuthenticator();
        $tfa_key = $ga->createSecret();

        $queryBuilder = database::$auth->createQueryBuilder();
        $queryBuilder->update('account')
            ->set('restore_key', '1')
            ->where('id = :id')
            ->setParameter('id', $userinfo['id']);
        $queryBuilder->executeQuery();

        // SOAP command (if configured)
        if (!empty(get_config('soap_2d_command'))) {
            $command = str_replace('{USERNAME}', $antiXss->xss_clean(strtoupper($userinfo['username'])), get_config('soap_2d_command'));
            RemoteCommandWithSOAP($command);
            $command = str_replace('{USERNAME}', $antiXss->xss_clean(strtoupper($userinfo['username'])), get_config('soap_2e_command'));
            $command = str_replace('{SECRET}', $tfa_key, $command);
            RemoteCommandWithSOAP($command);
        }

        $acc_name = str_replace('-', '', $acc_name);
        $acc_name = str_replace('.', '', $acc_name);
        $acc_name = str_replace('_', '', $acc_name);
        $acc_name = str_replace('@', '', $acc_name);

        $message = 'Two-Factor Authentication (2FA) Enabled。<br>Please scan the following QR code or manually enter the key：<br>';
        $message .= '<img src="' . $ga->getQRCodeGoogleUrl($acc_name, $tfa_key) . '"><br>';
        $message .= 'key: <b>' . $tfa_key . '</b>';

        send_phpmailer(strtolower($userinfo['email']), 'Account 2FA enabled', $message);
        success_msg(lang('check_your_email'));
    }
}