# Extending from a theme or mu-plugin

Site code can add fields and custom-table rules without editing the plugin.
Prefer an **mu-plugin** for anything that protects stored data: a theme change
must not remove a registry entry that existing rows still depend on.

```text
wp-content/mu-plugins/acme-encrypted-fields.php
```

## When registration runs

The plugin boots on `plugins_loaded` priority 5. Theme `functions.php` loads
later, so the plugin refreshes the registry and table adapters on
`after_setup_theme` priority 99.

- Add filters at file scope in `functions.php` or an mu-plugin.
- Other plugins should add filters on `plugins_loaded` (priority 10 or later).
- Do not register from `init` or later; encryption hooks may already be active.
- `kec_custom_table()` refreshes before retrying when the adapter is not
  found, so it can be resolved at theme file scope after the filter is
  registered.
- For value helpers called while `functions.php` is still loading, run
  `kec_plugin()->refreshExtensions()` first or call them from a runtime hook.

## Add fields

```php
add_filter('kec_field_registry', function (array $fields): array {
    $fields['user']['meta']['acme_phone'] = [
        'type' => 'text',
        'search' => true,
    ];

    $fields['post']['meta']['acme_reference'] = [
        'type' => 'text',
    ];

    return $fields;
});
```

The filter receives the active base registry (`KEC_FIELDS`,
`wp-content/kec-fields.php`, or the saved admin registry, in that order), then
adds or overrides fields. Use `kec_readonly_fields` to decrypt without
encrypting.

## Custom tables

Declare only the columns that must be encrypted:

```php
use EncryptedFields\Contracts\TableAdapterInterface;

final class Acme_Leads_Adapter implements TableAdapterInterface
{
    public function name(): string
    {
        return 'acme_leads';
    }

    public function table(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'acme_leads';
    }

    public function primaryKey(): string
    {
        return 'id';
    }

    public function columns(): array
    {
        return [
            'email' => 'email',
            'phone' => 'text',
            'name'  => 'text',
        ];
    }

    public function read(int $id): ?array
    {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT * FROM ' . $this->table() . ' WHERE ' . $this->primaryKey() . ' = %d',
                $id
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    public function write(int $id, array $data): bool
    {
        global $wpdb;

        $data = array_intersect_key($data, $this->columns());
        if (array() === $data) {
            return true;
        }

        $updated = $wpdb->update(
            $this->table(),
            $data,
            array($this->primaryKey() => $id)
        );

        return false !== $updated;
    }

    public function searchableColumns(): array
    {
        return ['email', 'phone'];
    }
}

add_filter('kec_table_adapters', function (array $adapters): array {
    $adapters['acme_leads'] = new Acme_Leads_Adapter();
    return $adapters;
});
```

The same adapter is used by `wp kec migrate --table=acme_leads`.

### Runtime read/write

The plugin cannot intercept arbitrary SQL from another plugin. Hook the other
plugin's read/save paths and use the adapter wrapper:

```php
$leads = kec_custom_table('acme_leads');

add_filter('acme_lead_row', function (array $row) use ($leads): array {
    return $leads->decryptRow($row);
});

add_filter('acme_lead_save', function (array $data) use ($leads): array {
    return $leads->encryptRow($data);
});

// Or use the adapter's own primary-key accessors:
$row = $leads->read(42);
$leads->write(42, ['email' => $email, 'phone' => $phone]);

// Single values use the same field domain as migration:
$cipher = $leads->encryptValue($email, 'email');
$plain  = $leads->decryptValue($cipher, 'email');
```

`read()` and `write()` encrypt/decrypt every column returned by `columns()`.
The wrapper passes undeclared keys through unchanged; the adapter decides
whether to persist them.

### Blind indexes for custom tables

Add your own indexed column (for example `email_bidx CHAR(64)`) and write the
token beside the ciphertext:

```php
$indexed = $leads->blindIndex('email', $email);
```

Query the indexed column with the same token. Tokens are HMAC-normalized and
bound to the field name.

## Value helpers

```php
$cipher = kec_encrypt_value($value, 'acme_lead', 'phone', ['type' => 'text']);
$plain  = kec_decrypt_value($cipher, 'acme_lead', 'phone', ['type' => 'text']);
$token  = kec_blind_index($value, 'acme_lead', 'phone');
$isEnc  = kec_is_encrypted($cipher);
```

- Use the **same** entity, field and options on read and write.
- If the field is registered, its registry definition wins over `$options`.
- Values must be scalar; arrays/objects throw instead of being stored
  unencrypted.
- `kec_encrypt_value()` throws when the key is missing or encryption fails;
  do not catch that and store plaintext.
- `kec_decrypt_value()` returns the input when a value is not decryptable.
- `kec_field()` returns the resolved `Field` object for advanced integrations.
- `kec_custom_table()` returns `null` for an unregistered adapter.

For custom tables, prefer `kec_custom_table()->encryptRow()` /
`decryptRow()` or `encryptValue()` / `decryptValue()` so fields use the same
domain as migration. Use `blindIndex()` for the indexed column.
