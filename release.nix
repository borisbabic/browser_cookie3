#   # Enter the environment
#   nix-shell release.nix
#
#   # create the package
#   python setup.py bdist # system specific
#   python setup.py sdist # for all 
#
#   # upload you package
#   twine upload dist/project_name-x.y.z.tar.gz
with import <nixpkgs> {};

(pkgs.python3.withPackages (ps: with ps; [twine setuptools])).env
