#!/bin/bash

# Function to get all enabled interface config paths
get_enabled_interfaces() {
    local interfaces_dir="db/interfaces"
    local configs=()
    
    # Check if interfaces directory exists and has interface configs
    if [ -d "$interfaces_dir" ]; then
        for interface_file in "$interfaces_dir"/*.json; do
            if [ -f "$interface_file" ]; then
                # Extract enabled status and config file path from interface JSON
                local enabled=$(jq -r '.enabled // false' "$interface_file" 2>/dev/null)
                local conf_path=$(jq -r '.config_file_path // empty' "$interface_file" 2>/dev/null)
                
                # Add to configs if enabled and config path exists
                if [ "$enabled" = "true" ] && [ -n "$conf_path" ] && [ "$conf_path" != "null" ]; then
                    configs+=("$conf_path")
                fi
            fi
        done
    fi
    
    # Fallback to legacy single interface if no multi-interface configs found
    if [ ${#configs[@]} -eq 0 ]; then
        local legacy_conf="$(jq -r .config_file_path db/server/global_settings.json 2>/dev/null || echo /etc/wireguard/wg0.conf)"
        if [ -f "$legacy_conf" ]; then
            configs+=("$legacy_conf")
        fi
    fi
    
    printf '%s\n' "${configs[@]}"
}

# manage wireguard stop/start with the container
case $WGUI_MANAGE_START in (1|t|T|true|True|TRUE)
    # Start all enabled interfaces
    while IFS= read -r conf; do
        if [ -f "$conf" ]; then
            echo "Starting WireGuard interface: $conf"
            wg-quick up "$conf" || echo "Failed to start $conf"
        fi
    done < <(get_enabled_interfaces)
    
    # Setup trap to stop all interfaces on container stop
    trap 'while IFS= read -r conf; do
        if [ -f "$conf" ]; then
            echo "Stopping WireGuard interface: $conf"
            wg-quick down "$conf" 2>/dev/null || true
        fi
    done < <(get_enabled_interfaces)' SIGTERM
esac

# manage wireguard restarts
case $WGUI_MANAGE_RESTART in (1|t|T|true|True|TRUE)
    # Monitor all enabled interface configs for changes
    while IFS= read -r conf; do
        [[ -f "$conf" ]] || touch "$conf" # inotifyd needs file to exist
        inotifyd - "$conf":w | while read -r event file; do
            echo "Config changed: $file - restarting interface"
            wg-quick down "$file" 2>/dev/null || true
            wg-quick up "$file" || echo "Failed to restart $file"
        done &
    done < <(get_enabled_interfaces)
esac


./wg-ui &
wait $!
