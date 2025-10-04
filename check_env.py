
import sys
import bcrypt

print("--- Python Environment Diagnostic ---")
print(f"Python Executable: {sys.executable}")
print("\n--- sys.path ---")
for p in sys.path:
    print(f"  - {p}")
print("\n--- Bcrypt Library Info ---")
try:
    print(f"Location of bcrypt module: {bcrypt.__file__}")
    # This is the line that fails in passlib
    version = getattr(getattr(bcrypt, '__about__', {}), '__version__', 'NOT FOUND')
    if version != 'NOT FOUND':
        print(f"Successfully read bcrypt version: {version}")
        print("CONCLUSION: The bcrypt library in this environment is CORRECT.")
    else:
        print("ERROR: The '__about__' attribute is missing.")
        print("CONCLUSION: The bcrypt library in this environment is INCORRECT or corrupted.")
except Exception as e:
    print(f"An error occurred while inspecting bcrypt: {e}")
    print("CONCLUSION: The bcrypt library in this environment is causing the error.")

print("\n--- End of Diagnostic ---")
