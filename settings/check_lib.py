import importlib

required_libraries = [
    "requests",
    "bs4",
    "jwt",
    "os"
    # 필요한 라이브러리를 여기에 추가하세요
]

missing_libraries = []
for library in required_libraries:
    if importlib.util.find_spec(library) is None:
        missing_libraries.append(library)

if missing_libraries:
    print("Require Library list:")
    for lib in missing_libraries:
        print(f"- {lib}")
    print("\n You can insatll Labrary through 'pip install <Lib name>'")
else:
    print("All required Library is ready")
    print("You can Start Diagnosis.")
