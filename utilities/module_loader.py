import os
import importlib

def load_all_modules_from_directory(directory):
    modules = {}
    package_name = directory.replace("/", ".")
    for filename in os.listdir(directory):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            module = importlib.import_module(f"{package_name}.{module_name}")
            modules[module_name] = module
    return modules