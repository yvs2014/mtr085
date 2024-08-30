:

set -e
RPM=rpms

cd $(dirname $0)/..
mkdir -p "$RPM"
RPMDEST="$(pwd)/$RPM"

rpmbuild -ba --define "_rpmdir $RPMDEST" package-templates/rpm-package-mtr085/mtr085.spec || :
cd -

#ls -lR "$RPM"
tree "$RPM"

