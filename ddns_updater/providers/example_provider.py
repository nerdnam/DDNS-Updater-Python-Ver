# ddns_updater/providers/example_provider.py
# TODO: Rename this file to match your provider, e.g., mynewdns_provider.py
# TODO: Update all "Example" and "example" references to your provider's name.

import json
import requests
# TODO: Import other necessary libraries (e.g., re for regex, hashlib for custom auth)

from .base_provider import BaseProvider

class ExampleProvider(BaseProvider): # TODO: Rename class
    NAME = "example"  # TODO: Set to your provider's short name (lowercase)
    # TODO: Define API endpoint constants if applicable
    # API_ENDPOINT = "https://api.example.com/ddns"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        # TODO: Read provider-specific settings from self.config
        # Example: self.api_key = self.config.get('example_api_key')
        #          self.username = self.config.get('example_username')
        
        # self.domain, self.owner are initialized by BaseProvider

        # TODO: Validate required settings and their formats
        # Example:
        # if not self.api_key:
        #     error_msg = f"{self.NAME.capitalize()} provider: 'example_api_key' is required."
        #     self.logger.error(error_msg)
        #     raise ValueError(error_msg)
        #
        # if not self.SOME_REGEX.match(self.api_key): # If API key has a specific format
        #     error_msg = f"{self.NAME.capitalize()} provider: 'example_api_key' format is invalid."
        #     self.logger.error(error_msg)
        #     raise ValueError(error_msg)
        pass # Remove pass when __init__ is implemented

    @staticmethod
    def get_required_config_fields():
        # TODO: List all configuration keys absolutely required for this provider.
        #       These will be checked by the core application.
        # Example: return ["example_api_key", "domain", "owner"]
        return ["domain", "owner"] # Placeholder, update this

    @staticmethod
    def get_optional_config_fields():
        # TODO: List optional configuration keys and their default values.
        # Example: return {"example_ttl": 300, "example_proxied": False}
        return {"ttl": None} # Placeholder, update this

    @staticmethod
    def get_description():
        # TODO: Provide a brief description of the provider.
        return "This is an example provider template. Replace with actual provider details."

    def _build_hostname_for_api(self):
        """
        Helper method to construct the hostname string as expected by the provider's API.
        This might be FQDN, just the owner part, or something else.
        Adjust based on the API documentation.
        """
        # TODO: Implement based on how your provider expects the hostname/record name.
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        return f"{owner}.{self.domain}"

    # TODO: Add any other private helper methods needed for API interaction
    #       (e.g., _build_auth_headers, _parse_api_response, _handle_api_error)

    def update_record(self, ip_address, record_type="A", proxied=None):
        # TODO: Implement the actual DDNS update logic here.
        # This will involve:
        # 1. Determining the correct API endpoint.
        # 2. Constructing the request payload or query parameters.
        # 3. Setting up authentication headers or parameters.
        # 4. Making the HTTP request (GET, POST, PUT, etc.).
        # 5. Parsing the API response.
        # 6. Handling success and error conditions based on status codes and response body.

        # Example structure (highly dependent on the actual API):
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update record for "
                         f"{self._build_hostname_for_api()} ({record_type}) to IP: {ip_address}")

        # --- 1. Prepare API request ---
        # target_url = self.API_ENDPOINT # Or construct dynamically
        # headers = { 'User-Agent': f'Python-DDNS-Updater/{self.NAME}' }
        # params = {} # For GET requests
        # data_payload = {} # For POST/PUT requests (often JSON)

        # TODO: Add authentication to headers or params (e.g., API key, token, basic auth)
        # if self.api_key:
        #     headers['Authorization'] = f'Bearer {self.api_key}'
        # auth_tuple = (self.username, self.password) # For Basic Auth

        # TODO: Set IP address and other necessary parameters
        # if record_type == "AAAA":
        #     params['myipv6'] = ip_address # Example
        # else:
        #     params['myip'] = ip_address   # Example
        # params['hostname'] = self._build_hostname_for_api()

        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            # TODO: Make the actual HTTP request
            # response = requests.get(target_url, params=params, headers=headers, timeout=timeout) # Example GET
            # response = requests.post(target_url, json=data_payload, headers=headers, timeout=timeout) # Example POST with JSON
            
            # --- Placeholder: Simulate an API call ---
            self.logger.warning(f"{self.NAME.capitalize()}: This is a template. Actual API call not implemented.")
            # Simulate success for testing purposes
            # return True, f"Successfully updated (simulated) {self._build_hostname_for_api()} to {ip_address}"
            # Simulate failure
            return False, "API call not implemented in example provider."
            # --- End Placeholder ---

            # TODO: Process the response
            # response_text = response.text.strip() if response.text else ""
            # self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # TODO: Check response.status_code and response_text for success/failure
            # if response.status_code == 200 and "some_success_keyword" in response_text.lower():
            #     self.logger.info(f"Successfully updated {self._build_hostname_for_api()} to {ip_address}.")
            #     return True, f"Successfully updated. API Response: '{response_text}'"
            # else:
            #     error_message = f"API Error: HTTP {response.status_code} - {response_text}"
            #     self.logger.error(error_message)
            #     return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"
        # except Exception as e: # Catch other potential errors during API interaction
        #     self.logger.exception(f"{self.NAME.capitalize()}: Unexpected error during update.")
        #     return False, f"Unexpected error: {e}"