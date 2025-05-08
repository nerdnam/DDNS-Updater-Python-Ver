# /ddns-updater-python-ver-ipv4/ddns_updater/providers/__init__.py
import os
import importlib
import inspect
import logging
from .base_provider import BaseProvider 

provider_loader_logger = logging.getLogger("ddns_updater.provider_loader")

_PROVIDER_CLASSES = {} 

def _load_providers():
    if _PROVIDER_CLASSES: 
        provider_loader_logger.debug("Providers already loaded.")
        return

    current_dir = os.path.dirname(os.path.abspath(__file__))
    provider_loader_logger.info(f"Loading providers from directory: {current_dir}")

    for filename in os.listdir(current_dir):
        if filename.endswith("_provider.py") and filename != "base_provider.py":
            module_name_short = filename[:-3] 
            module_import_path = f".{module_name_short}"
            
            try:
                module = importlib.import_module(module_import_path, package=__name__)
                provider_loader_logger.debug(f"Successfully imported module: {module_import_path}")
                
                for class_name, class_obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(class_obj, BaseProvider) and class_obj is not BaseProvider:
                        if hasattr(class_obj, 'NAME') and isinstance(class_obj.NAME, str) and class_obj.NAME:
                            provider_identifier = class_obj.NAME.lower() 
                            if provider_identifier in _PROVIDER_CLASSES:
                                provider_loader_logger.warning(
                                    f"Duplicate provider identifier '{provider_identifier}' found in module "
                                    f"'{module_name_short}'. Overwriting with class '{class_name}'. "
                                    f"Previous: {_PROVIDER_CLASSES[provider_identifier].__module__}.{_PROVIDER_CLASSES[provider_identifier].__name__}"
                                )
                            _PROVIDER_CLASSES[provider_identifier] = class_obj
                            provider_loader_logger.info(
                                f"Successfully loaded and registered provider: '{provider_identifier}' "
                                f"from module '{module_name_short}' (class: {class_name})"
                            )
                        else:
                            provider_loader_logger.warning(
                                f"Provider class '{class_name}' in module '{module_name_short}' "
                                f"is missing a valid 'NAME' string attribute. Skipping registration."
                            )
            except ImportError as e:
                provider_loader_logger.error(f"Error importing provider module '{module_name_short}': {e}", exc_info=True)
            except Exception as e:
                provider_loader_logger.error(f"Unexpected error loading provider from module '{module_name_short}': {e}", exc_info=True)

_load_providers() 

def get_provider_class(provider_name_from_config: str):
    if not provider_name_from_config:
        return None
    return _PROVIDER_CLASSES.get(provider_name_from_config.lower())

def get_supported_providers() -> list[dict]:
    providers_info = []
    for identifier, provider_class_obj in _PROVIDER_CLASSES.items():
        try:
            description = provider_class_obj.get_description()
            required_fields = provider_class_obj.get_required_config_fields()
            optional_fields_with_defaults = provider_class_obj.get_optional_config_fields()
            
            info = {
                "name": identifier, 
                "class_name": provider_class_obj.__name__, 
                "description": description,
                "required_fields": required_fields,
                "optional_fields": optional_fields_with_defaults 
            }
            providers_info.append(info)
        except Exception as e:
            provider_loader_logger.error(f"Error retrieving info for provider '{identifier}': {e}", exc_info=True)
            
    return sorted(providers_info, key=lambda p: p['name'])