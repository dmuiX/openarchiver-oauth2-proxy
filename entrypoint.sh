#!/bin/sh

# Helper to read secret from file if env var ends in _FILE
expand_secrets() {
    for var in $(env | grep '_FILE='); do
        var_name=$(echo "$var" | cut -d= -f1)
        file_path=$(echo "$var" | cut -d= -f2-)
        if [ -f "$file_path" ]; then
            base_var_name=$(echo "$var_name" | sed 's/_FILE$//')
            # Only export if not already set (allow override)
            if [ -z "$(eval echo \$$base_var_name)" ]; then
                export "$base_var_name"="$(cat "$file_path")"
                echo "Set $base_var_name from file"
            fi
        fi
    done
}

expand_secrets

# Verify required vars for the custom proxy
if [ -z "$JWT_SIGNING_KEY" ]; then
    echo "ERROR: JWT_SIGNING_KEY is missing!"
    exit 1
fi

echo "Starting OpenArchiver OAuth2 Proxy..."
exec /app/openarchiver-oauth2-proxy
