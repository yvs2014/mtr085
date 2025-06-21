:

set -e
RPM=rpms

dir0=$(dirname "$0")
cd "$dir0/.."
mkdir -p "$RPM"
RPMDEST="$(pwd)/$RPM"

rpmbuild -ba --define "_rpmdir $RPMDEST" package-templates/rpm-package/mtr085.spec || :
cd -

#ls -lR "$RPM"
tree "$RPM"

