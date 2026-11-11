<?php

namespace Koyo\EncryptedFields\Integrations\LegacyEcKoyo;

/**
 * Registry preset matching the EC-KOYO koyo_meta_cipher_map() fields.
 */
final class Preset
{
    /**
     * @return array<string, mixed>
     */
    public static function registry(): array
    {
        $email = array('type' => 'email', 'search' => true);
        $text = array('type' => 'text');
        $search = array('type' => 'text', 'search' => true);

        $userMeta = array(
            'first_name' => $search,
            'last_name' => $search,
            'billing_first_name' => $search,
            'billing_last_name' => $search,
            'billing_yomigana_first_name' => $search,
            'billing_yomigana_last_name' => $search,
            'billing_company' => $text,
            'billing_postcode' => $search,
            'billing_city' => $search,
            'billing_address_1' => $text,
            'billing_address_2' => $text,
            'billing_phone' => $search,
            'billing_email' => $email,
            'shipping_first_name' => $search,
            'shipping_last_name' => $search,
            'shipping_yomigana_first_name' => $search,
            'shipping_yomigana_last_name' => $search,
            'shipping_company' => $text,
            'shipping_postcode' => $search,
            'shipping_city' => $search,
            'shipping_address_1' => $text,
            'shipping_address_2' => $text,
            'shipping_phone' => $search,
            'shipping_email' => $email,
            'city' => $search,
            'building_name' => $text,
            'dateofbirth' => $search,
            'zipcode' => $search,
            'phone' => $search,
            'billing_first_name_kana' => $search,
            'billing_last_name_kana' => $search,
            'shipping_first_name_kana' => $search,
            'shipping_last_name_kana' => $search,
        );

        $postMeta = array(
            '_billing_first_name' => $search,
            '_billing_last_name' => $search,
            '_billing_yomigana_first_name' => $search,
            '_billing_yomigana_last_name' => $search,
            '_billing_company' => $text,
            '_billing_postcode' => $search,
            '_billing_city' => $search,
            '_billing_address_1' => $text,
            '_billing_address_2' => $text,
            '_billing_phone' => $search,
            '_billing_email' => $email,
            '_shipping_first_name' => $search,
            '_shipping_last_name' => $search,
            '_shipping_yomigana_first_name' => $search,
            '_shipping_yomigana_last_name' => $search,
            '_shipping_company' => $text,
            '_shipping_postcode' => $search,
            '_shipping_city' => $search,
            '_shipping_address_1' => $text,
            '_shipping_address_2' => $text,
            '_shipping_phone' => $search,
            '_customer_ip_address' => $text,
            '_customer_user_agent' => $text,
            '_billing_address_index' => $text,
            '_shipping_address_index' => $text,
        );

        return array(
            'user' => array(
                'columns' => array(
                    'user_login' => array('type' => 'login', 'max_length' => 60),
                    'user_email' => array('type' => 'email', 'max_length' => 100),
                ),
                'meta' => $userMeta,
            ),
            'post' => array(
                'post_types' => array('shop_order'),
                'meta' => $postMeta,
            ),
        );
    }

    /**
     * Map for KEC_LEGACY.
     *
     * - ctr_key:   EC-KOYO encrypt()/decrypt() AES-256-CTR key (hex)
     * - login_key: EC-KOYO encrypt_login()/decrypt_login() AES-256-CBC key (hex)
     * - email_key: EC-KOYO encrypt_decrypt() secret_key
     * - email_iv:  EC-KOYO encrypt_decrypt() secret_iv
     *
     * Secrets are read from constants/environment and are never bundled here.
     *
     * @return array<string, string>
     */
    public static function legacyConfig(): array
    {
        return array(
            'ctr_key' => self::secret('KEC_LEGACY_CTR_KEY', 'KOYO_LEGACY_CTR_KEY'),
            'login_key' => self::secret('KEC_LEGACY_LOGIN_KEY', 'KOYO_LEGACY_LOGIN_KEY'),
            'email_key' => self::secret('KEC_LEGACY_EMAIL_KEY', 'KOYO_LEGACY_EMAIL_KEY'),
            'email_iv' => self::secret('KEC_LEGACY_EMAIL_IV', 'KOYO_LEGACY_EMAIL_IV'),
        );
    }

    private static function secret(string $primary, string $fallback): string
    {
        if (defined($primary)) {
            return (string) constant($primary);
        }

        if (defined($fallback)) {
            return (string) constant($fallback);
        }

        $env = getenv($primary);
        if (is_string($env) && '' !== $env) {
            return $env;
        }

        $env = getenv($fallback);
        if (is_string($env) && '' !== $env) {
            return $env;
        }

        return '';
    }
}
