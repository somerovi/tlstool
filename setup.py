from distutils.core import setup

setup(
    name="TLSTool",
    version="1.0.1",
    description="TLSTool for creating certificates",
    author="Samir Omerovic",
    author_email="somerovi@gmail.com",
    py_modules=["tlstool"],
    entry_points={"console_scripts": ["tlstool=tlstool:cli"]},
    install_requires=["black==19.3b0", "Jinja2==2.10", "PyYAML==5.1"],
)
