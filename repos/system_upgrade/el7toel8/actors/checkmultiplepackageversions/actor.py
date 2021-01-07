from leapp.actors import Actor
from leapp.libraries.common.rpms import has_package
from leapp.models import InstalledRPM, Report
from leapp.reporting import create_report, Title, Summary, Severity, Flags, Remediation, RelatedResource
from leapp.tags import IPUWorkflowTag, ChecksPhaseTag


class CheckMultiplePackageVersions(Actor):
    """
    Check for problematic 32bit packages installed together with 64bit ones.

    If a known problematic 32bit package is found, the upgrade will be inhibited with the detailed
    report how to solve the problem if suck a remedy exists.
    """

    name = 'multiple_package_versions'
    consumes = (InstalledRPM,)
    produces = (Report,)
    tags = (IPUWorkflowTag, ChecksPhaseTag)

    def process(self):
        # package_name: remedy information
        problem_package_map = {
                'brlapi.i686': {'bugzilla': None},
                'gnome-online-accounts-devel.i686': {
                    'bugzilla': 'https://bugzilla.redhat.com/show_bug.cgi?id=1765627'},
                'geocode-glib-devel.i686': {
                    'bugzilla': 'https://bugzilla.redhat.com/show_bug.cgi?id=1765629'}}
        actual_problems = []
        for package in problem_package_map:
            name, arch = package.split('.')
            if has_package(InstalledRPM, name, arch) and has_package(InstalledRPM, name, 'x86_64'):
                actual_problems.append(package)
        if actual_problems:
            remediation = ["yum", "remove", "-y"] + actual_problems
            # generate RelatedResources for the report
            related_resources = []
            for package in actual_problems:
                related_resources.append(RelatedResource('package', package))
                if problem_package_map[package]['bugzilla']:
                    related_resources.append(RelatedResource('bugzilla', problem_package_map[package]['bugzilla']))
            # create a single report entry for all problematic packages
            create_report([
                Title('Some packages have both 32bit and 64bit version installed which are known to be incompatible'),
                Summary('The following packages have both 32bit and 64bit version installed which are known to be '
                        'incompatible in RHEL8:\n{}'.format('\n'.join(['-{}'.format(a) for a in actual_problems]))),
                Severity(Severity.HIGH),
                Flags([Flags.INHIBITOR]),
                Remediation(commands=[remediation])] + related_resources)
