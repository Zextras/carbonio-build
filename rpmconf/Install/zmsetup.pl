#!/usr/bin/perl
#
# SPDX-FileCopyrightText: 2022 Synacor, Inc.
# SPDX-FileCopyrightText: 2022 Zextras <https://www.zextras.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;

use lib "/opt/zextras/libexec";
use lib "/opt/zextras/common/lib/perl5";
use Zimbra::Util::Common;
use Zimbra::Util::Timezone;
use FileHandle;
use Net::LDAP;
use IPC::Open3;
use Cwd;
use Time::localtime qw(ctime);

$|=1; # don't buffer stdout

our $platform = qx(/opt/zextras/libexec/get_plat_tag.sh);
chomp $platform;
my $logFileName = "zmsetup.".getDateStamp().".log";
my $logfile = "/tmp/".$logFileName;
open LOGFILE, ">$logfile" or die "Can't open $logfile: $!\n";
unlink("/tmp/zmsetup.log") if (-e "/tmp/zmsetup.log");
symlink($logfile, "/tmp/zmsetup.log");

my $ol = select (LOGFILE);
select ($ol);
$| = 1;

progress("Operations logged to $logfile\n");

our $ZMPROV = "/opt/zextras/bin/zmprov -r -m -l";
our $SU = "su - zextras -c ";

my $filename="/opt/zextras/conf/localconfig.xml";
my $uid = (stat $filename)[4];
my $user = (getpwuid $uid)[0];

if ($user ne "zextras") {
    progress ("\n\nERROR\n\n");
    progress ("/opt/zextras/conf/localconfig.xml is not owned by zextras\n");
    progress ("This will cause installation failure.\n");
    exit (1);
}

use preinstall;
use postinstall;
use Getopt::Std;
use Net::DNS::Resolver;
use NetAddr::IP;

our %options = ();
our %config = ();
our %loaded = ();
our %saved = ();

my @packageList = (
  "carbonio-core",
  "carbonio-directory-server",
  "carbonio-logger",
  "carbonio-mta",
  "carbonio-appserver",
  "carbonio-memcached",
  "carbonio-proxy",
);

my %packageServiceMap = (
  amavis    => "carbonio-mta",
  antivirus => "carbonio-mta",
  antispam  => "carbonio-mta",
  opendkim  => "carbonio-mta",
  cbpolicyd => "carbonio-mta",
  mta       => "carbonio-mta",
  logger    => "carbonio-logger",
  mailbox   => "carbonio-appserver",
  ldap      => "carbonio-directory-server",
  stats     => "carbonio-core",
  memcached => "carbonio-memcached",
  proxy     => "carbonio-proxy",
  service   => "carbonio-appserver",
  zimbra    => "carbonio-appserver",
  zimbraAdmin   => "carbonio-appserver",
  zimlet    => "carbonio-appserver",
);

my @webappList = (
  "service",
  "zimbra",
  "zimbraAdmin",
  "zimlet",
);

my %installedPackages = ();
our %installedWebapps = ();
my %prevInstalledPackages = ();
my %enabledPackages = ();
my %enabledServices = ();

my %installStatus = ();
our %configStatus = ();
our %migratedStatus= ();

my $prevVersion = "";
our $curVersion = "";
my ($prevVersionMinor,$prevVersionMajor,$prevVersionMicro,$prevVersionBuild);
my ($curVersionMinor,$curVersionMajor,$curVersionMicro,$curVersionMicroMicro,$curVersionType,$curVersionBuild);
our $newinstall = 1;
chomp (my $ldapSchemaVersion = do {
    local $/ = undef;
    open my $fh, "<", "/opt/zextras/conf/attrs-schema"
        or die "could not open /opt/zextras/conf/attrs-schema: $!";
    <$fh>;
});

my $ldapConfigured = 0;
my $haveSetLdapSchemaVersion = 0;
my $ldapRunning = 0;
my $sqlConfigured = 0;
my $sqlRunning = 0;
my $loggerSqlConfigured = 0;
my $loggerSqlRunning = 0;
my @installedServiceList = ();
my @enabledServiceList = ();

my $ldapRootPassChanged = 0;
my $ldapAdminPassChanged = 0;
my $ldapRepChanged = 0;
my $ldapPostChanged = 0;
my $ldapAmavisChanged = 0;
my $ldapNginxChanged = 0;
my $ldapReplica = 0;
my $starttls = 0;
my $needNewCert = "";
my $ssl_cert_type = "self";

my @ssl_digests = ("ripemd160","sha","sha1","sha224","sha256","sha384","sha512");
my @interfaces = ();

($>) and usage();

getopts("c:hd", \%options) or usage();

my $debug = $options{d};

usage() if ($options{h});

if (isInstalled("carbonio-directory-server")) {
  if ($newinstall || ! -f "/opt/zextras/data/ldap/config/cn\=config.ldif") {
    installLdapConfig();
  }
}

if(isInstalled("carbonio-directory-server")) {
  installLdapSchema();
}

if (! $newinstall ) {
  if ( -f "/opt/zextras/conf/ca/ca.pem" ) {
    progress("Adding /opt/zextras/conf/ca/ca.pem to cacerts\n");
    main::runAsZextras("/opt/zextras/bin/zmcertmgr addcacert /opt/zextras/conf/ca/ca.pem");
  }
}

getInstalledPackages();

unless (isEnabled("carbonio-core")) {
  progress("carbonio-core must be enabled.");
  exit 1;
}

getInstalledWebapps();

if ($options{d}) {
  foreach my $pkg (keys %installedPackages) {
    detail("Package $pkg is installed");
  }
  foreach my $pkg (keys %enabledPackages) {
    detail("Package $pkg is $enabledPackages{$pkg}");
  }
}

setDefaults();
setDefaultsFromLocalConfig() if (! $newinstall);

setEnabledDependencies();

checkPortConflicts();

getSystemStatus();

startLdap() if ($ldapConfigured);

if (!$newinstall) {
  my $rc = runAsZextras ("/opt/zextras/libexec/zmldapupdateldif");
}

if ($ldapConfigured ||
  (($config{LDAPHOST} ne $config{HOSTNAME}) && ldapIsAvailable())) {
  setLdapDefaults();
  getAvailableComponents();
}

if ($options{c}) {
  loadConfig ($options{c});
  applyConfig();
} else {
  if ($configStatus{BEGIN} eq "CONFIGURED" &&
    $configStatus{END}  ne "CONFIGURED") {
    resumeConfiguration();
  }
  if (!$newinstall) {
    my $m = createMainMenu();
    if (checkMenuConfig($m)) {
      applyConfig();
    }
  }
  mainMenu();
}

setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersion', $curVersion);
setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMajor', $curVersionMajor);
setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMinor', $curVersionMinor);
setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMicro', $curVersionMicroMicro);
setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionType', $curVersionType);
setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionBuild', $curVersionBuild);

close LOGFILE;
chmod 0600, $logfile;
if (-d "/opt/zextras/log") {
  main::progress("Moving $logfile to /opt/zextras/log\n");
  system("cp -f $logfile /opt/zextras/log/");
  system("chown zextras:zextras /opt/zextras/log/$logFileName");
}

################################################################
# End Main
################################################################

################################################################
# Subroutines
################################################################

sub usage {
  ($>) and print STDERR "Warning: $0 must be run as root!\n\n";
  print STDERR "Usage: $0 [-h] [-c <config file>]\n";
  print STDERR "\t-h: display this help message\n";
  print STDERR "\t-c: configure with values in <config file>\n\n";
  exit 1;
}

sub progress {
  my $msg = shift;
  print "$msg";
  my ($sub,$line) = (caller(1))[3,2];
  $msg = "$sub:$line $msg" if $options{d};
  detail ($msg);
}

sub detail {
  my $msg = shift;
  my ($sub,$line) = (caller(1))[3,2];
  my $date = ctime();
  $msg =~ s/\n$//;
  $msg = "$sub:$line $msg" if $options{d};
  open(LOG, ">>$logfile");
  print LOG "$date $msg\n";
  close(LOG);
  #qx(echo "$date $msg" >> $logfile);
}

sub defineInstallWebapps {
  if (!defined $config{INSTALL_WEBAPPS}) {
    $config{INSTALL_WEBAPPS} = "zimlet";
    if ($config{SERVICEWEBAPP} eq "yes") {
      $config{INSTALL_WEBAPPS} = "service $config{INSTALL_WEBAPPS}";
    }
    if ($config{UIWEBAPPS} eq "yes") {
      $config{INSTALL_WEBAPPS} = "$config{INSTALL_WEBAPPS} zimbra zimbraAdmin";
    }
  }
}

sub saveConfig {
  my $fname = "/opt/zextras/config.$$";

  if (open CONF, ">$fname") {
    progress ("Saving config in $fname...");
    foreach (sort keys %config) {
      # Don't write passwords or previous INSTALL_PACKAGES
      if (/PASS|INSTALL_PACKAGES/) {next;}
      print CONF qq($_="$config{$_}"\n);
    }
    print CONF qq(INSTALL_PACKAGES=");
    foreach (@packageList) {
      my $el = $_;
      if (grep (/$el/, keys %installedPackages)) {
        print CONF "$_ ";
      }
    }
    print CONF qq("\n);
    close CONF;
    chmod 0600, $fname;
    progress ("done.\n");
  } else {
    progress( "Can't open $fname: $!\n");
  }
}

sub loadConfig {
  my $filename = shift;
  open (CONF, $filename) or die "Can't open $filename: $!";
  my @lines = <CONF>;
  close CONF;
  foreach (@lines) {
    chomp;
    my ($k, $v) = split ('=', $_, 2);
    $v=~s/"//g;
    $config{$k} = $v;
  }

  $config{ALLOWSELFSIGNED} = "true";
}

sub checkPortConflicts {
  progress ( "Checking for port conflicts\n" );
  my %needed = (
    25 => 'carbonio-mta',
    80 => 'carbonio-appserver',
    110 => 'carbonio-appserver',
    143 => 'carbonio-appserver',
    389 => 'carbonio-directory-server',
    443 => 'carbonio-appserver',
    636 => 'carbonio-directory-server',
    993 => 'carbonio-appserver',
    995 => 'carbonio-appserver',
    7025 => 'carbonio-appserver',
    7071 => 'carbonio-appserver',
    7072 => 'carbonio-appserver',
    7306 => 'carbonio-appserver',
    7307 => 'carbonio-appserver',
    8465 => 'carbonio-mta',
    10024 => 'carbonio-mta',
    10025 => 'carbonio-mta',
    10026 => 'carbonio-mta',
    10027 => 'carbonio-mta',
    10028 => 'carbonio-mta',
    10029 => 'carbonio-mta',
    10030 => 'carbonio-mta',
  );

  open PORTS, "netstat -an | egrep '^tcp' | grep LISTEN | awk '{print \$4}' | sed -e 's/.*://' |";
  my @ports = <PORTS>;
  close PORTS;
  chomp @ports;

  my $any = 0;
  foreach (@ports) {
    if (defined ($needed{$_}) && isEnabled($needed{$_})) {
      unless ($needed{$_} eq "carbonio-directory-server" && $newinstall == 0) {
        $any = 1;
        progress ( "Port conflict detected: $_ ($needed{$_})\n" );
      }
    }
  }

  if (!$options{c}) {
    if ($any) { ask("Port conflicts detected! - Press Enter/Return key to continue", ""); }
  }

}

sub isComponentAvailable {
  my $component = shift;
  detail("checking isComponentAvailable $component");
  # if its already defined return;
  if (exists $main::loaded{components}{$component}) {
    return 1;
  }
  if ($ldapConfigured ||
    (($config{LDAPHOST} ne $config{HOSTNAME}) && ldapIsAvailable())) {
    getAvailableComponents();
  }
  if (exists $main::loaded{components}{$component}) {
    detail("Component $component is available.");
    return 1;
  } else {
    detail("Component $component is not available.");
    return 0;
  }

}

sub getAvailableComponents {
  detail("Getting available components");
  open(ZM, "$ZMPROV gcf zimbraComponentAvailable 2> /dev/null|") or
    return undef;
  while (<ZM>) {
    chomp;
    if (/^zimbraComponentAvailable: (\S+)/) {
      $main::loaded{components}{$1} = "zimbraComponentAvailable";
    }
  }
  close(ZM) or return undef;
}

sub getDateStamp() {
  my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time());
  $year = 1900+$year;
  $sec = sprintf("%02d", $sec);
  $min = sprintf("%02d", $min);
  $hour = sprintf("%02d", $hour);
  $mday = sprintf("%02d", $mday);
  $mon = sprintf("%02d", $mon+1);
  my $stamp = "$year$mon$mday-$hour$min$sec";
  return $stamp;
}

sub getInstalledPackages {
  detail("Getting installed packages");
  foreach my $p (@packageList) {
    if (isInstalled($p)) {
      $installedPackages{$p} = $p;
    }
  }

  # get list of previously installed packages on upgrade
  if ($newinstall == 0) {
    $config{zimbra_server_hostname} = getLocalConfig ("zimbra_server_hostname")
      if ($config{zimbra_server_hostname} eq "");
    detail ("DEBUG: zimbra_server_hostname=$config{zimbra_server_hostname}")
      if $options{d};

    $config{ldap_url} = getLocalConfig ("ldap_url")
      if ($config{ldap_url} eq "");
    detail ("DEBUG: ldap_url=$config{ldap_url}")
      if $options{d};

    if (index($config{ldap_url}, "/".$config{zimbra_server_hostname}) != -1) {
      detail ("zimbra_server_hostname contained in ldap_url checking ldap status");
      if (startLdap()) {return 1;}
    } else {
      detail ("zimbra_server_hostname not in ldap_url not starting slapd");
    }
    detail("Getting installed services from ldap");
    open(ZMPROV, "$ZMPROV gs $config{zimbra_server_hostname}|");
    while (<ZMPROV>) {
      chomp;
      if (/zimbraServiceInstalled:\s(.*)/) {
        my $service = $1;
	if ($service eq "imapproxy") {
		$service = "proxy";
	}
        if (exists $packageServiceMap{$service}) {
          detail ("Marking $service as previously installed.")
            if ($debug);
          $prevInstalledPackages{$packageServiceMap{$service}} = "Installed";
        } else {
          progress("WARNING: Unknown package installed for $service.\n");
        }
      } else {
        detail ("DEBUG: skipping not zimbraServiceInstalled =>  $_") if $debug;
      }
    }
  }

}

sub getInstalledWebapps {
  detail("Determining installed web applications");
  my $webappsDir = "/opt/zextras/jetty/webapps";
  foreach my $app (@webappList) {
    if (($newinstall && -d "$webappsDir/$app") ||
        (!$newinstall && isServiceEnabled($app))) {
      $installedWebapps{$app}="Enabled";
      detail("Web application $app is enabled.");
    } else {
      if ($newinstall || (!$newinstall && $installedWebapps{$app} ne "Enabled")) {
        $installedWebapps{$app}="Disabled";
      }
    }
  }
  if (!$newinstall && !defined($config{INSTALL_WEBAPPS})) {
    foreach my $app (%installedWebapps) {
      if ($installedWebapps{$app} eq "Enabled") {
        $config{INSTALL_WEBAPPS}="$app $config{INSTALL_WEBAPPS}";
      }
    }
  }
}

sub isServiceEnabled {
  my $service = shift;

  if (defined ($enabledServices{$service})) {
    if ($enabledServices{$service} eq "Enabled") {
      detail ("$service is enabled");
      return 1;
    } else {
      detail("$service is not enabled");
      return undef;
    }
  } else {
    detail("$service not in enabled cache");
  }

  return undef;
}

sub isEnabled {
  my $package = shift;
  detail("checking isEnabled $package");
  # if its already defined return;
  if (defined $enabledPackages{$package}) {
    if ($enabledPackages{$package} eq "Enabled") {
      detail("$package is enabled");
      return 1;
    } else {
      detail("$package is not enabled");
      return undef;
    }
  } else {
    detail("$package not in enabled cache");
    my $packages = join(" ", keys %enabledPackages);
    detail("enabled packages $packages");
  }


  # lookup service in ldap
  if ($newinstall == 0) {
    $config{zimbra_server_hostname} = getLocalConfig ("zimbra_server_hostname")
      if ($config{zimbra_server_hostname} eq "");
    detail ("DEBUG: zimbra_server_hostname=$config{zimbra_server_hostname}")
      if $options{d};

    $config{ldap_url} = getLocalConfig ("ldap_url")
      if ($config{ldap_url} eq "");
    detail ("DEBUG: ldap_url=$config{ldap_url}")
      if $options{d};

    if (index($config{ldap_url}, "/".$config{zimbra_server_hostname}) != -1) {
      detail ("zimbra_server_hostname contained in ldap_url checking ldap status");
      if (startLdap()) {return 1;}
    } else {
      detail ("zimbra_server_hostname not in ldap_url not starting slapd");
    }
    detail("Getting enabled services from ldap");
    $enabledPackages{"carbonio-core"} = "Enabled"
      if (isInstalled("carbonio-core"));

    open(ZMPROV, "$ZMPROV gs $config{zimbra_server_hostname}|");
    while (<ZMPROV>) {
      chomp;
      if (/zimbraServiceEnabled:\s(.*)/) {
        my $service = $1;
	if ($service eq "imapproxy") {
		$service = "proxy";
	}
        if (exists $packageServiceMap{$service}) {
          detail ("Marking $service as an enabled service.")
            if ($debug);
          $enabledPackages{$packageServiceMap{$service}} = "Enabled";
          $enabledServices{$service} = "Enabled";
        } else {
          progress("WARNING: Unknown package installed for $service.\n");
        }
      } else {
        detail ("DEBUG: skipping not zimbraServiceEnabled => $_") if $debug;
      }
    }
    foreach my $p (@packageList) {
      if (isInstalled($p) and not defined $prevInstalledPackages{$p}) {
        detail("Marking $p as installed. Services for $p will be enabled.");
        $enabledPackages{$p} = "Enabled";
      } elsif (isInstalled($p) and not defined $enabledPackages{$p}) {
        detail("Marking $p as disabled.");
        $enabledPackages{$p} = "Disabled";
      }
    }
    close(ZMPROV);
  } else {
    detail("Newinstall enabling all installed packages");
    foreach my $p (@packageList) {
      if (isInstalled($p)) {
        unless ($enabledPackages{$p} eq "Disabled") {
          detail("Enabling $p");
          $enabledPackages{$p} = "Enabled"
        }
      }
    }
  }

  $enabledPackages{$package} = "Disabled"
    if ($enabledPackages{$package} ne "Enabled");

  return ($enabledPackages{$package} eq "Enabled" ? 1 : 0);
}

sub isInstalled {
  my $pkg = shift;

  my $pkgQuery;

  my $good = 0;
  if ($platform =~ /^DEBIAN/ || $platform =~ /^UBUNTU/) {
    $pkgQuery = "dpkg -s $pkg";
  } else {
    $pkgQuery = "rpm -q $pkg";
  }

  my $rc = 0xffff & system ("$pkgQuery > /dev/null 2>&1");
  $rc >>= 8;
  if (($platform =~ /^DEBIAN/ || $platform =~ /^UBUNTU/) && $rc == 0 ) {
    $good = 1;
    $pkgQuery = "dpkg -s $pkg | egrep '^Status: ' | grep 'not-installed'";
    $rc = 0xffff & system ("$pkgQuery > /dev/null 2>&1");
    $rc >>= 8;
    return ($rc == $good);
  } else {
    return ($rc == $good);
  }
}

sub genRandomPass {
  open RP, "/opt/zextras/bin/zmjava com.zimbra.common.util.RandomPassword -l 8 10|" or
    die "Can't generate random password: $!\n";
  my $rp = <RP>;
  close RP;
  chomp $rp;
  return $rp;
}

sub getSystemStatus {

  if (isEnabled("carbonio-directory-server")) {
    if (-f "/opt/zextras/data/ldap/mdb/db/data.mdb") {
      $ldapConfigured = 1;
      $ldapRunning = 0xffff & system("/opt/zextras/bin/ldap status > /dev/null 2>&1");
      if ($ldapRunning) {
        $ldapRunning = 0;
      } else {
        $ldapRunning = 1;
      }
      # Mac on x86 choked on this line?
      #$ldapRunning = ($ldapRunning)?0:1;
    } else {
      $config{DOCREATEDOMAIN} = "yes";
    }
  }

  if (isEnabled("carbonio-appserver")) {
    if (-d "/opt/zextras/db/data/zimbra") {
      $sqlConfigured = 1;
      $sqlRunning = 0xffff & system("/opt/zextras/bin/mysqladmin status > /dev/null 2>&1");
      $sqlRunning = ($sqlRunning)?0:1;
    }
    if ($newinstall) {
      $config{DOCREATEADMIN} = "yes";
      $config{DOTRAINSA} = "yes";
    }
  }

  if (isEnabled("carbonio-logger")) {
    if (-d "/opt/zextras/logger/db/data/zimbra_logger") {
      $loggerSqlConfigured = 1;
      $loggerSqlRunning = 0xffff &
        system("/opt/zextras/bin/logmysqladmin status > /dev/null 2>&1");
      $loggerSqlRunning = ($loggerSqlRunning)?0:1;
    }
  }

  if (isEnabled("carbonio-mta")) {
    $config{SMTPHOST} = $config{HOSTNAME} if ($config{SMTPHOST} eq "");
  }
}

sub getAllServers {
  my ($service) = @_;
  my @servers;
  detail("Running $ZMPROV gas $service");
  open(ZMPROV, "$ZMPROV gas $service 2>/dev/null|");
  chomp(@servers = <ZMPROV>);
  close(ZMPROV);

  return @servers;
}

sub getLdapAccountValue($$) {
  my ($attrib,$sub) = @_;
  my ($val,$err);
  my $sec="acct";
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val = $main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached config attribute for Account $sub: $attrib=$val");
    return $val;
  }
  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV ga $sub";
  my $pid = open3($wfh,$rfh,$efh,$cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    return undef;
  } elsif ($? & 127) {
    # died with signal
    return undef;
  } else {
    $rc = $? >> 8;
    return undef if ($rc != 0);
  }
  $val=$main::loaded{$sec}{$sub}{$attrib};
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  detail("Returning retrieved account config attribute for $sub: $attrib=$val");
  return $val;
}

sub getLdapCOSValue {
  my ($attrib,$sub) = @_;

  $sub = "default" if ($sub eq "");
  my $sec="gc";
  my ($val,$err);
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val=$main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached cos config attribute for $sub: $attrib=$val");
    return $val;
  }

  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gc $sub";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    close $rfh; close $efh;
    return undef;
  } elsif ($? & 127) {
    # died with signal
    close $rfh; close $efh;
    return undef;
  } else {
    $rc = $? >> 8;
    close $rfh; close $efh;
    return undef if ($rc != 0);
  }
  close $rfh; close $efh;
  $val=$main::loaded{$sec}{$sub}{$attrib};
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  detail("Returning retrieved cos config attribute for $sub: $attrib=$val");
  return $val;
}

sub getLdapConfigValue {
  my $attrib = shift;
  my ($val,$err);
  my $sec="gcf";
  my $sub=$sec;
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val=$main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached global config attribute: $attrib=$val");
    return $val;
  }
  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gacf";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    close $rfh; close $efh;
    return undef;
  } elsif ($? & 127) {
    # died with signal
    close $rfh; close $efh;
    return undef;
  } else {
    $rc = $? >> 8;
    close $rfh; close $efh;
    return undef if ($rc != 0);
  }
  close $rfh; close $efh;
  $val=$main::loaded{$sec}{$sub}{$attrib};
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  detail("Returning retrieved global config attribute $attrib=$val");
  return $val;
}

sub getLdapDomainValue {
  my ($attrib,$sub) = @_;

  $sub = $config{zimbraDefaultDomainName}
    if ($sub eq "");

  return undef if ($sub eq "");
  my $sec="domain";

  my ($val,$err);
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val = $main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached domain config attribute for $sub: $attrib=$val");
    return $val;
  }

  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gd $sub";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    close $rfh; close $efh;
    return undef;
  } elsif ($? & 127) {
    # died with signal
    close $rfh; close $efh;
    return undef;
  } else {
    $rc = $? >> 8;
    close $rfh; close $efh;
    return undef if ($rc != 0);
  }
  close $rfh; close $efh;
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  $val=$main::loaded{$sec}{$sub}{$attrib};
  detail("Returning retrieved domain config attribute for $sub: $attrib=$val");
  return $val;
}

sub getLdapServerValue {
  my ($attrib,$sub) = @_;
  $sub = $main::config{HOSTNAME} if ($sub eq "");
  my $sec="gs";
  my ($val,$err);
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val = $main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached server config attribute for $sub: $attrib=$val");
    return $val;
  }
  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gs $sub";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    close $rfh; close $efh;
    return undef;
  } elsif ($? & 127) {
    # died with signal
    close $rfh; close $efh;
    return undef;
  } else {
    $rc = $? >> 8;
    close $rfh; close $efh;
    return undef if ($rc != 0);
  }
  close $rfh; close $efh;
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  $val = $main::loaded{$sec}{$sub}{$attrib};
  detail("Returning retrieved server config attribute for $sub: $attrib=$val");
  return $val;
}


sub getRealLdapServerValue {
  my ($attrib,$sub) = @_;
  $sub = $main::config{HOSTNAME} if ($sub eq "");
  my $sec="gsreal";
  my ($val,$err);
  if (exists $main::loaded{$sec}{$sub}{$attrib}) {
    $val = $main::loaded{$sec}{$sub}{$attrib};
    detail("Returning cached server config attribute for $sub: $attrib=$val");
    return $val;
  }
  my ($rfh,$wfh,$efh,$cmd,$rc);
  $rfh = new FileHandle;
  $wfh = new FileHandle;
  $efh = new FileHandle;
  $cmd = "$ZMPROV gs -e $sub";
  my $pid = open3($wfh,$rfh,$efh, $cmd);
  unless(defined($pid)) {
    return undef;
  }
  close $wfh;
  my @d = <$rfh>;
  while (scalar(@d) > 0)  {
    chomp(my $line = shift(@d));
    my ($k, $v) = $line =~ m/^(\w+):\s(.*)/;
    while ($d[0] !~ m/^\w+:\s.*/ && scalar(@d) > 0) {
      chomp($v .= shift(@d));
    }
    if (!$main::loaded{$sec}{$sub}{zmsetuploaded} || ($main::loaded{$sec}{$sub}{zmsetuploaded} && $k eq $attrib)) {
      if (exists $main::loaded{$sec}{$sub}{$k}) {
        $main::loaded{$sec}{$sub}{$k}="$main::loaded{$sec}{$sub}{$k}\n$v";
      } else {
        $main::loaded{$sec}{$sub}{$k}="$v";
      }
    }
  }
  chomp($err = join "", <$efh>);
  detail("$err") if (length($err) > 0);
  waitpid($pid,0);
  if ($? == -1) {
    # failed to execute
    close $rfh; close $efh;
    return undef;
  } elsif ($? & 127) {
    # died with signal
    close $rfh; close $efh;
    return undef;
  } else {
    $rc = $? >> 8;
    close $rfh; close $efh;
    return undef if ($rc != 0);
  }
  close $rfh; close $efh;
  $main::loaded{$sec}{$sub}{zmsetuploaded}=1;
  $val = $main::loaded{$sec}{$sub}{$attrib};
  detail("Returning retrieved server config attribute for $sub: $attrib=$val");
  return $val;
}

sub setLdapDefaults {

  return if exists $config{LDAPDEFAULTSLOADED};
  progress ( "Setting defaults from ldap..." );

  #
  # Load server specific attributes only if server exists
  #
  my $serverid = getLdapServerValue("zimbraId");
  if ($serverid ne "")  {

    $config{zimbraIPMode}          = getLdapServerValue("zimbraIPMode");
    $config{zimbraDNSMasterIP}     = getLdapServerValue("zimbraDNSMasterIP");
    $config{zimbraDNSUseTCP}       = getLdapServerValue("zimbraDNSUseTCP");
    $config{zimbraDNSUseUDP}       = getLdapServerValue("zimbraDNSUseUDP");
    $config{zimbraDNSTCPUpstream}  = getLdapServerValue("zimbraDNSTCPUpstream");

    $config{IMAPPORT}              = getLdapServerValue("zimbraImapBindPort");
    $config{IMAPSSLPORT}           = getLdapServerValue("zimbraImapSSLBindPort");
    $config{REMOTEIMAPBINDPORT}    = getLdapServerValue("zimbraRemoteImapBindPort");
    $config{REMOTEIMAPSSLBINDPORT} = getLdapServerValue("zimbraRemoteImapSSLBindPort");
    $config{POPPORT}               = getLdapServerValue("zimbraPop3BindPort");
    $config{POPSSLPORT}            = getLdapServerValue("zimbraPop3SSLBindPort");

    $config{IMAPPROXYPORT}         = getLdapServerValue("zimbraImapProxyBindPort");
    $config{IMAPSSLPROXYPORT}      = getLdapServerValue("zimbraImapSSLProxyBindPort");
    $config{POPPROXYPORT}          = getLdapServerValue("zimbraPop3ProxyBindPort");
    $config{POPSSLPROXYPORT}       = getLdapServerValue("zimbraPop3SSLProxyBindPort");
    $config{MAILPROXY}             = getLdapServerValue("zimbraReverseProxyMailEnabled");

    $config{MODE}                  = getLdapServerValue("zimbraMailMode");
    $config{PROXYMODE}             = getLdapServerValue("zimbraReverseProxyMailMode");
    $config{HTTPPORT}              = getLdapServerValue("zimbraMailPort");
    $config{HTTPSPORT}             = getLdapServerValue("zimbraMailSSLPort");

    $config{HTTPPROXYPORT}         = getLdapServerValue("zimbraMailProxyPort");
    $config{HTTPSPROXYPORT}        = getLdapServerValue("zimbraMailSSLProxyPort");
    $config{HTTPPROXY}             = getLdapServerValue("zimbraReverseProxyHttpEnabled");
    $config{SMTPHOST}              = getLdapServerValue("zimbraSmtpHostname");


    $config{zimbraReverseProxyLookupTarget} = getLdapServerValue("zimbraReverseProxyLookupTarget")
      if ($config{zimbraReverseProxyLookupTarget} eq "");

    if (isEnabled("carbonio-mta")) {
      my $tmpval = getLdapServerValue("zimbraMtaMyNetworks");
      $config{zimbraMtaMyNetworks} = $tmpval
        unless ($tmpval eq "");
    }
  }

  #
  # Load Global config values
  #
  # default domainname
  $config{zimbraDefaultDomainName} = getLdapConfigValue("zimbraDefaultDomainName");
  if ($config{zimbraDefaultDomainName} eq "") {
    $config{zimbraDefaultDomainName} = $config{CREATEDOMAIN};
  } else {
    $config{CREATEDOMAIN} = $config{zimbraDefaultDomainName};
    $config{CREATEADMIN} = "zextras\@$config{CREATEDOMAIN}";
  }

  if ($config{SMTPHOST} eq "") {
      my $smtphost = getLdapConfigValue("zimbraSmtpHostname");
      $smtphost =~ s/\n/ /g;
      $config{SMTPHOST} = $smtphost if ($smtphost ne "localhost");
  }

  $config{TRAINSASPAM}      = getLdapConfigValue("zimbraSpamIsSpamAccount");
  if ($config{TRAINSASPAM} eq "") {
    $config{TRAINSASPAM} = "spam.".lc(genRandomPass()).'@'.$config{CREATEDOMAIN};
  }
  $config{TRAINSAHAM}       = getLdapConfigValue("zimbraSpamIsNotSpamAccount");
  if ($config{TRAINSAHAM} eq "") {
    $config{TRAINSAHAM} = "ham.".lc(genRandomPass()).'@'.$config{CREATEDOMAIN};
  }
  $config{VIRUSQUARANTINE}       = getLdapConfigValue("zimbraAmavisQuarantineAccount");
  if ($config{VIRUSQUARANTINE} eq "") {
    $config{VIRUSQUARANTINE} = "virus-quarantine.".lc(genRandomPass()).'@'.$config{CREATEDOMAIN};
  }

  #
  # Load default COS
  #
  $config{USEKBSHORTCUTS} = getLdapCOSValue("zimbraPrefUseKeyboardShortcuts");
  $config{zimbraPrefTimeZoneId}=getLdapCOSValue("zimbraPrefTimeZoneId");

  #
  # Load default domain values
  #
  my $galacct = getLdapDomainValue("zimbraGalAccountId");
  $config{ENABLEGALSYNCACCOUNTS}=(($galacct eq "") ? "no" : "yes");

  #
  # Set some sane defaults if values were missing in LDAP
  #
  $config{HTTPPORT} = 80 if ($config{HTTPPORT} eq 0);
  $config{HTTPSPORT} = 443 if ($config{HTTPSPORT} eq 0);
  $config{MODE} = "https" if ($config{MODE} eq "");
  $config{PROXYMODE} = "https" if ($config{PROXYMODE} eq "");
  $config{REMOTEIMAPBINDPORT} = 8143 if ($config{REMOTEIMAPBINDPORT} eq 0);
  $config{REMOTEIMAPSSLBINDPORT} = 8993 if ($config{REMOTEIMAPSSLBINDPORT} eq 0);

  if (isInstalled("carbonio-proxy") && isEnabled("carbonio-proxy")) {
     if ($config{MAILPROXY} eq "TRUE") {
        if ($config{IMAPPORT} == $config{IMAPPROXYPORT} && $config{IMAPPORT} == 143) {
            $config{IMAPPORT} = 7143;
        }
        if ($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT} && $config{IMAPSSLPORT} == 993) {
            $config{IMAPSSLPORT} = 7993;
        }
        if ($config{POPPORT} == $config{POPPROXYPORT} && $config{POPPORT} == 110) {
            $config{POPPORT} = 7110;
        }
        if ($config{POPSSLPORT} == $config{POPSSLPROXYPORT} && $config{POPSSLPORT} == 995) {
            $config{POPSSLPORT} = 7995;
        }
        if ($config{IMAPPORT} == $config{IMAPPROXYPORT} && $config{IMAPPORT} == 7143) {
            $config{IMAPPROXYPORT} = 143;
        }
        if ($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT} && $config{IMAPSSLPORT} == 7993) {
            $config{IMAPSSLPROXYPORT} = 993;
        }
        if ($config{POPPORT} == $config{POPPROXYPORT} && $config{POPPORT} == 7110) {
            $config{POPPROXYPORT} = 110;
        }
        if ($config{POPSSLPORT} == $config{POPSSLPROXYPORT} && $config{POPSSLPORT} == 7995) {
            $config{POPSSLPROXYPORT} = 995;
        }
     }
     if ($config{HTTPPROXY} eq "TRUE") {
        if ($config{HTTPPORT} == $config{HTTPPROXYPORT} && $config{HTTPPORT} == 80) {
            $config{HTTPPORT} = 8080;
        }
        if ($config{HTTPSPORT} == $config{HTTPSPROXYPORT} && $config{HTTPSPORT} == 443) {
            $config{HTTPSPORT} = 8443;
        }
        if ($config{HTTPPORT} == $config{HTTPPROXYPORT} && $config{HTTPPORT} == 8080) {
            $config{HTTPPROXYPORT} = 80;
        }
        if ($config{HTTPSPORT} == $config{HTTPSPROXYPORT} && $config{HTTPSPORT} == 8443) {
            $config{HTTPSPROXYPORT} = 443;
        }
     }
  } else {
        if ($config{IMAPPORT} == $config{IMAPPROXYPORT} && $config{IMAPPORT} == 143) {
            $config{IMAPPROXYPORT} = 7143;
        }
        if ($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT} && $config{IMAPSSLPORT} == 993) {
            $config{IMAPSSLPROXYPORT} = 7993;
        }
        if ($config{POPPORT} == $config{POPPROXYPORT} && $config{POPPORT} == 110) {
            $config{POPPROXYPORT} = 7110;
        }
        if ($config{POPSSLPORT} == $config{POPSSLPROXYPORT} && $config{POPSSLPORT} == 995) {
            $config{POPSSLPROXYPORT} = 7995;
        }
        if ($config{IMAPPORT} == $config{IMAPPROXYPORT} && $config{IMAPPORT} == 7143) {
            $config{IMAPPORT} = 143;
        }
        if ($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT} && $config{IMAPSSLPORT} == 7993) {
            $config{IMAPSSLPORT} = 993;
        }
        if ($config{POPPORT} == $config{POPPROXYPORT} && $config{POPPORT} == 7110) {
            $config{POPPORT} = 110;
        }
        if ($config{POPSSLPORT} == $config{POPSSLPROXYPORT} && $config{POPSSLPORT} == 7995) {
            $config{POPSSLPORT} = 995;
        }
        if ($config{HTTPPORT} == $config{HTTPPROXYPORT} && $config{HTTPPORT} == 80) {
            $config{HTTPPROXYPORT} = 8080;
        }
        if ($config{HTTPSPORT} == $config{HTTPSPROXYPORT} && $config{HTTPSPORT} == 443) {
            $config{HTTPSPROXYPORT} = 8443;
        }
        if ($config{HTTPPORT} == $config{HTTPPROXYPORT} && $config{HTTPPORT} == 8080) {
            $config{HTTPPORT} = 80;
        }
        if ($config{HTTPSPORT} == $config{HTTPSPROXYPORT} && $config{HTTPSPORT} == 8443) {
            $config{HTTPSPORT} = 443;
        }
  }

  #
  # debug output
  #
  if ($options{d}) {
    foreach my $key (sort keys %config) {
      print "\tDEBUG: $key=$config{$key}\n";
    }
  }
  $config{LDAPDEFAULTSLOADED}=1;
  progress ( "done.\n" );
}

sub installLdapConfig {
  my $config_src="/opt/zextras/common/etc/openldap/zimbra/config";
  my $config_dest="/opt/zextras/data/ldap/config";
  if (-d "/opt/zextras/data/ldap/config") {
    main::progress("Installing LDAP configuration database...");
    qx(mkdir -p $config_dest/cn\=config/olcDatabase\=\{2\}mdb);
    system("cp -f $config_src/cn\=config.ldif $config_dest/cn\=config.ldif");
    system("cp -f $config_src/cn\=config/cn\=module\{0\}.ldif $config_dest/cn\=config/cn\=module\{0\}.ldif");
    system("cp -f $config_src/cn\=config/cn\=schema.ldif $config_dest/cn\=config/cn\=schema.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{-1\}frontend.ldif $config_dest/cn\=config/olcDatabase\=\{-1\}frontend.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{0\}config.ldif $config_dest/cn\=config/olcDatabase\=\{0\}config.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{1\}monitor.ldif $config_dest/cn\=config/olcDatabase\=\{1\}monitor.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{2\}mdb.ldif $config_dest/cn\=config/olcDatabase\=\{2\}mdb.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{0\}dynlist.ldif $config_dest/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{0\}dynlist.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{1\}unique.ldif $config_dest/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{1\}unique.ldif");
    system("cp -f $config_src/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{2\}noopsrch.ldif $config_dest/cn\=config/olcDatabase\=\{2\}mdb/olcOverlay\=\{2\}noopsrch.ldif");
    qx(chmod 600 $config_dest/cn\=config.ldif);
    qx(chmod 600 $config_dest/cn\=config/*.ldif);
    qx(chown -R zextras:zextras $config_dest);
    main::progress("done.\n");
  }
}

sub installLdapSchema {
  main::runAsZextras("/opt/zextras/libexec/zmldapschema 2>/dev/null");
}

sub setDefaults {
  progress ( "Setting defaults..." ) unless $options{d};

  # Get the interfaces.
  # Do this in perl, since it's the same on all platforms.
  my $ipv4found=0;
  my $ipv6found=0;

  open INTS, "/sbin/ifconfig | grep ' addr' |";
  foreach (<INTS>) {
    chomp;
    if ($_ =~ /inet6/) {
      next if ($_ =~ /Link/);
      s/.*inet6 //;
      s/.*addr: //;
      s/\/.*//;
      if ($_ ne "::1") {
        $ipv6found=1;
      }
    } else {
      s/.*inet //;
      s/\s.*//;
      s/[a-zA-Z:]//g;
      s/^\n//g;
      next if ($_ eq "");
      if ($_ ne "127.0.0.1") {
        $ipv4found=1;
      }
    }
    push @interfaces, $_;
  }
  close INTS;
  if (-x "/sbin/ip") {
    open INTS, "/sbin/ip addr| grep ' scope ' |";
    foreach (<INTS>) {
      chomp;
      if ($_ =~ /inet6/) {
        next if ($_ =~ /link/);
        s/.*inet6 //;
        s/.*addr: //;
        s/\/.*//;
        if ($_ ne "::1") {
          $ipv6found=1;
        }
      } else {
        s/.*inet //;
        s/\/.*//;
        s/[a-zA-Z:]//g;
        s/^\n//g;
        next if ($_ eq "");
        if ($_ ne "127.0.0.1") {
          $ipv4found=1;
        }
      }
      push @interfaces, $_;
    }
    close INTS;
  }

  my %seen=();
  @interfaces = grep {!$seen{$_}++} @interfaces;

  $config{EXPANDMENU} = "no";
  $config{REMOVE} = "no";
  $config{UPGRADE} = "yes";
  $config{LDAPPORT} = 389;

  $config{IMAPPORT} = 143;
  $config{IMAPSSLPORT} = 993;
  $config{POPPORT} = 110;
  $config{POPSSLPORT} = 995;
  $config{HTTPPORT} = 80;
  $config{HTTPSPORT} = 443;
  $config{ssl_default_digest} = "sha256";

  if (!$ipv4found && $ipv6found) {
    $config{zimbraIPMode}     = "ipv6";
  } else {
    $config{zimbraIPMode}     = "ipv4";
  }

  $config{JAVAHOME} = "/opt/zextras/common/lib/jvm/java";
  setLocalConfig ("zimbra_java_home", "$config{JAVAHOME}");
  $config{HOSTNAME} = lc(qx(hostname --fqdn));
  chomp $config{HOSTNAME};

  $config{ldap_dit_base_dn_config} = "cn=zimbra"
    if ($config{ldap_dit_base_dn_config} eq "");
  $config{mailboxd_directory} = "/opt/zextras/mailboxd";
  if ( -f "/opt/zextras/common/jetty_home/start.jar" ) {
    $config{mailboxd_keystore} = "$config{mailboxd_directory}/etc/keystore";
    $config{mailboxd_server} = "jetty";
  } elsif ( -f "/opt/zextras/tomcat/bin/startup.sh" ) {
    $config{mailboxd_keystore} = "$config{mailboxd_directory}/conf/keystore";
    $config{mailboxd_server} = "tomcat";
  } else {
    $config{mailboxd_keystore} = "/opt/zextras/conf/keystore";
  }
  $config{mailboxd_truststore} = "/opt/zextras/common/lib/jvm/java/lib/security/cacerts";
  $config{mailboxd_keystore_password} = genRandomPass();
  $config{mailboxd_truststore_password} = "changeit";

  $config{SMTPHOST} = "";
  $config{DOCREATEDOMAIN} = "no";
  my $sHostname = lc(qx(hostname -s));
  chomp $sHostname;
  $config{CREATEDOMAIN} = $config{HOSTNAME};
  $config{CREATEDOMAIN} =~ s/$sHostname\.//g;
  $config{DOCREATEADMIN} = "no";

  if (isEnabled("carbonio-appserver")) {
    progress  "setting defaults for carbonio-appserver.\n" if $options{d};
    $config{DOCREATEADMIN} = "yes" if $newinstall;
    $config{DOTRAINSA} = "yes";
    $config{SERVICEWEBAPP} = "yes";
    $config{UIWEBAPPS} = "yes";
    $config{zimbraReverseProxyLookupTarget} = "TRUE" if $newinstall;
    $config{zimbraMailProxy} = "TRUE" if $newinstall;
    $config{zimbraWebProxy} = "TRUE" if $newinstall;

    # default values for upgrades
    if ($config{TRAINSASPAM} eq "") {
      $config{TRAINSASPAM} = "spam.".lc(genRandomPass());
      $config{TRAINSASPAM} .= '@'.$config{CREATEDOMAIN};
    }
    if ($config{TRAINSAHAM} eq "") {
      $config{TRAINSAHAM} = "ham.".lc(genRandomPass());
      $config{TRAINSAHAM} .= '@'.$config{CREATEDOMAIN};
    }
    if ($config{VIRUSQUARANTINE} eq "") {
      $config{VIRUSQUARANTINE} = "virus-quarantine.".lc(genRandomPass());
      $config{VIRUSQUARANTINE} .= '@'.$config{CREATEDOMAIN};
    }
  }

  $config{zimbra_require_interprocess_security} = 0;
  $config{ZIMBRA_REQ_SECURITY}="no";

  if (isEnabled("carbonio-directory-server")) {
    progress "setting defaults for carbonio-directory-server.\n" if $options{d};
    $config{DOCREATEDOMAIN} = "yes" if $newinstall;
    $config{LDAPROOTPASS} = genRandomPass();
    $config{LDAPADMINPASS} = $config{LDAPROOTPASS};
    $config{LDAPREPPASS} =  $config{LDAPADMINPASS};
    $config{LDAPPOSTPASS} = $config{LDAPADMINPASS};
    $config{LDAPAMAVISPASS} =  $config{LDAPADMINPASS};
    $config{ldap_nginx_password} = $config{LDAPADMINPASS};
    $config{LDAPREPLICATIONTYPE} = "master"; # Values can be master, mmr, replica
    $config{LDAPSERVERID} = 2; # Aleady enabled master should be 1, so default to next ID.
    $ldapRepChanged = 1;
    $ldapPostChanged = 1;
    $ldapAmavisChanged = 1;
    $ldapNginxChanged = 1;
  }

  if(isInstalled("carbonio-proxy") && !isEnabled("carbonio-directory-server")) {
    $config{ldap_nginx_password} = genRandomPass();
    $ldapNginxChanged = 1;
  }

  $config{CREATEADMIN} = "zextras\@$config{CREATEDOMAIN}";

  my $tzname=qx(/bin/date '+%Z');
  chomp($tzname);

  detail("Local timezone detected as $tzname\n");
  my $tzdata = Zimbra::Util::Timezone->parse;
  my $tz = $tzdata->gettzbyname($tzname);
  $config{zimbraPrefTimeZoneId} = $tz->tzid if (defined $tz);
  $config{zimbraPrefTimeZoneId} = 'America/Los_Angeles'
    if ($config{zimbraPrefTimeZoneId} eq "");
  detail("Default Olson timezone name $config{zimbraPrefTimeZoneId}\n");

  #progress("tzname=$tzname tzid=$config{zimbraPrefTimeZoneId}");

  $config{zimbra_ldap_userdn} = "uid=zimbra,cn=admins,$config{ldap_dit_base_dn_config}";

  $config{SMTPSOURCE} = $config{CREATEADMIN};
  $config{SMTPDEST} = $config{CREATEADMIN};
  $config{AVUSER} = $config{CREATEADMIN};
  $config{AVDOMAIN} = $config{CREATEDOMAIN};
  $config{STARTSERVERS} = "yes";

  if (isEnabled("carbonio-mta")) {
    progress  "setting defaults for carbonio-mta.\n" if $options{d};
    my @tmpval = (qx(/opt/zextras/libexec/zmserverips -n));
    chomp(@tmpval);
    if (@tmpval) {
      $config{zimbraMtaMyNetworks} = "@tmpval";
    } else {
      $config{zimbraMtaMyNetworks} = "127.0.0.0/8 [::1]/128 @interfaces";
    }
    $config{postfix_mail_owner} = "postfix";
    $config{postfix_setgid_group} = "postdrop";
  }

  $config{MODE} = "https";
  $config{PROXYMODE} = "https";

  $config{SYSTEMMEMORY} = getSystemMemory();
  $config{MYSQLMEMORYPERCENT} = mysqlMemoryPercent($config{SYSTEMMEMORY});
  $config{MAILBOXDMEMORY} = mailboxdMemoryMB($config{SYSTEMMEMORY});

  $config{CREATEADMINPASS} = $config{LDAPROOTPASS};

  if (!$options{c} && $newinstall) {
    progress "no config file and newinstall checking dns resolution\n" if $options{d};

    if (lookupHostName ($config{HOSTNAME}, 'A')) {
      if (lookupHostName ($config{HOSTNAME}, 'AAAA')) {
        progress("\n\nDNS ERROR resolving $config{HOSTNAME}\n");
        progress("It is suggested that the hostname be resolvable via DNS\n");
        if (askYN("Change hostname","Yes") eq "yes") {
          setHostName();
        }
      }
    }

    my $good = 0;

    if ($config{DOCREATEDOMAIN} eq "yes") {
      my $ans = getDnsRecords($config{CREATEDOMAIN}, 'MX');
      if (!defined($ans)) {
        progress("\n\nDNS ERROR resolving MX for $config{CREATEDOMAIN}\n");
        progress("It is suggested that the domain name have an MX record configured in DNS\n");
        if (askYN("Change domain name?","Yes") eq "yes") {
          setCreateDomain();
        }
      } elsif (isEnabled("carbonio-mta")) {

        my @answer = $ans->answer;
        foreach my $a (@answer) {
          if ($a->type eq "MX") {
            my $h = getDnsRecords ($a->exchange,'A');
            my $ipv6 = 0;
            if (!defined $h) {
              $h = getDnsRecords ($a->exchange, 'AAAA');
              $ipv6 = 1;
            }
            if (defined $h) {
              my @ha = $h->answer;
              foreach $h (@ha) {
                if ($ipv6) {
                  if ($h->type eq 'AAAA') {
                    progress "\tMX: ".$a->exchange." (".$h->address.")\n";
                  }
                } else {
                  if ($h->type eq 'A') {
                    progress "\tMX: ".$a->exchange." (".$h->address.")\n";
                  }
                }
              }
            } else {
              progress "\n\nDNS ERROR - No A or AAAA record for $config{CREATEDOMAIN}.\n";
            }
          }
        }
        progress "\n";
        foreach my $i (@interfaces) {
          progress "\tInterface: $i\n";
        }
        foreach my $a (@answer) {
          foreach my $i (@interfaces) {
            if ($a->type eq "MX") {
              my $h = getDnsRecords ($a->exchange,'A');
              if (!defined $h) {
                $h = getDnsRecords ($a->exchange, 'AAAA');
              }
              if (defined $h) {
                my @ha = $h->answer;
                foreach $h (@ha) {
                  my $interIp = NetAddr::IP->new("$i");
                  my $interface= lc($interIp->addr);
                  if ($h->type eq 'A' || $h->type eq 'AAAA') {
                    print "\t\t".$h->address."\n";
                    if ($h->address eq $interface) {
                      $good = 1;
                      last;
                    }
                  }
                }
                if ($good) { last; }
              }
            }
          }
          if ($good) {last;}
        }
        if (!$good) {
          progress ("\n\nDNS ERROR - none of the MX records for $config{CREATEDOMAIN}\n");
          progress ("resolve to this host\n");
          if (askYN("Change domain name?","Yes") eq "yes") {
            setCreateDomain();
          }
        }

      }
    }

  }
  if (isInstalled("carbonio-proxy")) {
    progress  "setting defaults for carbonio-proxy.\n" if $options{d};
    $config{STRICTSERVERNAMEENABLED} = "TRUE";
    $config{IMAPPROXYPORT} = 143;
    $config{IMAPSSLPROXYPORT} = 993;
    $config{POPPROXYPORT} = 110;
    $config{POPSSLPROXYPORT} = 995;
    $config{IMAPPORT} = 7143;
    $config{IMAPSSLPORT} = 7993;
    $config{POPPORT} = 7110;
    $config{POPSSLPORT} = 7995;
    $config{MAILPROXY} = "TRUE";
    $config{HTTPPROXY} = "TRUE";
    $config{HTTPPROXYPORT} = 8080;
    $config{HTTPSPROXYPORT} = 8443;
    $config{HTTPPORT} = 80;
    $config{HTTPSPORT} = 443;
  } else {
    $config{IMAPPROXYPORT} = 7143;
    $config{IMAPSSLPROXYPORT} = 7993;
    $config{POPPROXYPORT} = 7110;
    $config{POPSSLPROXYPORT} = 7995;
    $config{HTTPPROXYPORT} = 8080;
    $config{HTTPSPROXYPORT} = 8443;
  }

  if ($options{d}) {
    foreach my $key (sort keys %config) {
      print "\tDEBUG: $key=$config{$key}\n";
    }
  }

  progress ( "done.\n" );
}

sub setDefaultsFromLocalConfig {
  progress ("Setting defaults from existing config...");
  $config{HOSTNAME} = getLocalConfig ("zimbra_server_hostname");
  $config{HOSTNAME} = lc ($config{HOSTNAME});
  my $ldapUrl = getLocalConfig ("ldap_master_url");
  my $ld = (split ' ', $ldapUrl)[0];
  my $p = $ld;
  $p =~ s/ldaps?:\/\///;
  $p =~ s/.*:?//;
  if ($p ne "") {
    $config{LDAPPORT} = $p;
  } else {
    $p = getLocalConfig ("ldap_port");
    if ($p ne "") {
      $config{LDAPPORT} = $p;
    }
  }
  my $h = $ld;
  chomp($h);
  $h =~ s/"//g;
  $h =~ s/ldaps?:\/\///g;
  $h =~ s/:\d+//g;
  if ($h ne "") {
    $config{LDAPHOST} = $h;
  } else {
    $h = getLocalConfig ("ldap_host");
    if ($h ne "") {
      $config{LDAPHOST} = $h;
    }
  }
  $config{ldap_url} = getLocalConfig("ldap_url");
  $config{LDAPROOTPASS} = getLocalConfig ("ldap_root_password");
  $config{LDAPADMINPASS} = getLocalConfig ("zimbra_ldap_password");
  $config{SQLROOTPASS} = getLocalConfig ("mysql_root_password");
  $config{ZIMBRASQLPASS} = getLocalConfig ("zimbra_mysql_password");
  $config{MAILBOXDMEMORY} = getLocalConfig ("mailboxd_java_heap_size");
  $config{mailboxd_directory} = getLocalConfig("mailboxd_directory");
  $config{mailboxd_keystore} = getLocalConfig("mailboxd_keystore");
  $config{mailboxd_keystore_password} = getLocalConfig ("mailboxd_keystore_password")
    if (getLocalConfig("mailboxd_keystore_password") ne "");
  $config{mailboxd_truststore_password} = getLocalConfig ("mailboxd_truststore_password")
    if (getLocalConfig("mailboxd_truststore_password") ne "");
  $config{zimbra_ldap_userdn} = getLocalConfig("zimbra_ldap_userdn")
    if (getLocalConfig("zimbra_ldap_userdn") ne "");

  $config{zimbra_require_interprocess_security} = getLocalConfig("zimbra_require_interprocess_security");
  if ($config{zimbra_require_interprocess_security}) {
     $config{ZIMBRA_REQ_SECURITY} = "yes";
  } else {
     $config{ZIMBRA_REQ_SECURITY} = "no";
  }

  $config{ldap_dit_base_dn_config} = getLocalConfig("ldap_dit_base_dn_config");
  $config{ldap_dit_base_dn_config} = "cn=zimbra"
    if ($config{ldap_dit_base_dn_config} eq "");

  $config{SMTPSOURCE} = getLocalConfig("smtp_source");
  $config{SMTPSOURCE} = $config{CREATEADMIN}
    if ($config{SMTPSOURCE} eq "");

  $config{SMTPDEST} = getLocalConfig("smtp_destination");
  $config{SMTPDEST} = $config{CREATEADMIN}
    if ($config{SMTPDEST} eq "");

  $config{AVUSER} = getLocalConfig("av_notify_user");
  $config{AVUSER} = $config{CREATEADMIN}
    if ($config{AVUSER} eq "");

  $config{AVDOMAIN} = getLocalConfig("av_notify_domain");
  $config{AVDOMAIN} = $config{CREATEDOMAIN}
    if ($config{AVDOMAIN} eq "");

  if (isEnabled("carbonio-mta")) {
    $config{postfix_mail_owner} = getLocalConfig ("postfix_mail_owner");
    if ($config{postfix_mail_owner} eq "") {
      $config{postfix_mail_owner} = "postfix";
    }
    $config{postfix_setgid_group} = getLocalConfig ("postfix_setgid_group");
    if ($config{postfix_setgid_group} eq "") {
      $config{postfix_setgid_group} = "postdrop";
    }

  }

  if (isEnabled("carbonio-directory-server")) {
    $config{LDAPREPPASS} = getLocalConfig ("ldap_replication_password");
    if ($config{LDAPREPPASS} eq "") {
      $config{LDAPREPPASS} = $config{LDAPADMINPASS};
      $ldapRepChanged = 1;
    }
  }
  if (isEnabled("carbonio-directory-server") || isEnabled("carbonio-mta")) {
    $config{LDAPPOSTPASS} = getLocalConfig ("ldap_postfix_password");
    if ($config{LDAPPOSTPASS} eq "") {
      $config{LDAPPOSTPASS} = $config{LDAPADMINPASS};
      $ldapPostChanged = 1;
    }
    $config{LDAPAMAVISPASS} = getLocalConfig ("ldap_amavis_password");
    if ($config{LDAPAMAVISPASS} eq "") {
      $config{LDAPAMAVISPASS} = $config{LDAPADMINPASS};
      $ldapAmavisChanged = 1;
    }
  }
  if (isEnabled("carbonio-directory-server") || isEnabled("carbonio-proxy")) {
    $config{ldap_nginx_password} = getLocalConfig ("ldap_nginx_password");
    if ($config{ldap_nginx_password} eq "") {
      $config{ldap_nginx_password} = $config{LDAPADMINPASS};
      $ldapNginxChanged = 1;
    }
  }
  if ($options{d}) {
    foreach my $key (sort keys %config) {
      print "\tlc DEBUG: $key=$config{$key}\n";
    }
  }
  progress("done.\n");
}

sub ask {
  my $prompt = shift;
  my $default = shift;
  if ($default eq "") {
    print "$prompt ";
  } else {
    print "$prompt [$default] ";
  }
  my $rc = <>;
  chomp $rc;
  if ($rc eq "") {return $default;}
  return $rc;
}

sub askPassword {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    # although they are valid pass characters avoid $ and |
    # here because they cause quoting problems.
    if ($v =~ /\$|\\/g) {
      print "Invalid metacharater used.\n";
      next;
    }
    if ($v ne "") {return $v;}
    print "A non-blank answer is required\n";
  }
}

sub askYN {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    $v = lc($v);
    $v = substr ($v,0,1);
    if ($v eq "y") {return "yes";}
    if ($v eq "n") {return "no";}
    print "A Yes/No answer is required\n";
  }
}

sub askTF {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    $v = lc($v);
    $v = substr ($v,0,1);
    if ($v eq "t") {return "TRUE";}
    if ($v eq "f") {return "FALSE";}
    print "A True/False answer is required\n";
  }
}

sub askNum {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    my $i = int($v);
    if ($v eq $i) { return $v; }
    print "A numeric response is required!\n";
  }
}

sub askPositiveInt {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    my $i = int($v);
    if ($v eq $i && $v > 0) { return $v; }
    print "A positive integer response is required!\n";
  }
}

sub askNonBlank {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    if ($v ne "") {return $v;}
    print "A non-blank answer is required\n";
  }
}

sub askFileName {
  my $prompt = shift;
  my $default = shift;
  while (1) {
    my $v = ask($prompt, $default);
    if ($v ne "" && -f $v) {return $v;}
    print "A non-blank answer is required\n" if ($v eq "");
    print "$v must exist and be readable\n" if (!-f $v && $v ne "");
  }
}

sub setCreateDomain {
  my $oldDomain = $config{CREATEDOMAIN};
  my $good = 0;
  while (1) {
    $config{CREATEDOMAIN} =
      ask("Create domain:",
        $config{CREATEDOMAIN});
    my $ans = getDnsRecords($config{CREATEDOMAIN}, 'MX');
    if (!defined ($ans)) {
      progress("\n\nDNS ERROR resolving MX for $config{CREATEDOMAIN}\n");
      progress("It is suggested that the domain name have an MX record configured in DNS\n");
      if (askYN("Re-Enter domain name?","Yes") eq "no") {
        last;
      }
      $config{CREATEDOMAIN} = $oldDomain;
      next;
    } elsif (isEnabled("carbonio-mta")) {
      my @answer = $ans->answer;
      foreach my $a (@answer) {
        if ($a->type eq "MX") {
          my $h = getDnsRecords ($a->exchange,'A');
          my $ipv6 = 0;
          if (!defined $h) {
            $h = getDnsRecords ($a->exchange, 'AAAA');
            $ipv6 = 1;
          }
          if (defined $h) {
            my @ha = $h->answer;
            foreach $h (@ha) {
              if ($ipv6) {
                if ($h->type eq 'AAAA') {
                  progress "\tMX: ".$a->exchange." (".$h->address.")\n";
                }
              } else {
                if ($h->type eq 'A') {
                  progress "\tMX: ".$a->exchange." (".$h->address.")\n";
                }
              }
            }
          } else {
            progress "\n\nDNS ERROR - No A or AAAA record for $config{CREATEDOMAIN}.\n";
          }
        }
      }
      progress "\n";
      foreach my $i (@interfaces) {
        progress "\tInterface: $i\n";
      }
      foreach my $a (@answer) {
        foreach my $i (@interfaces) {
          if ($a->type eq "MX") {
            my $h = getDnsRecords ($a->exchange,'A');
            if (!defined $h) {
              $h = getDnsRecords ($a->exchange, 'AAAA');
            }
            if (defined $h) {
              my @ha = $h->answer;
              foreach $h (@ha) {
                my $interIp = NetAddr::IP->new("$i");
                my $interface= lc($interIp->addr);
                if ($h->type eq 'A' || $h->type eq 'AAAA') {
                  if ($h->address eq $interface) {
                    $good = 1;
                    last;
                  }
                }
              }
            }
            if ($good) { last; }
          }
        }
        if ($good) { last; }
      }
      if ($good) { last; }
      else {
        progress ("\n\nDNS ERROR - none of the MX records for $config{CREATEDOMAIN}\n");
        progress ("resolve to this host\n");
        progress ("It is suggested that the MX record resolve to this host\n");
        if (askYN("Re-Enter domain name?","Yes") eq "no") {
          last;
        }
        $config{CREATEDOMAIN} = $oldDomain;
        next;
      }
    }
    last;
  }
  my ($u,$d) = split ('@', $config{CREATEADMIN});
  my $old = $config{CREATEADMIN};
  $config{CREATEADMIN} = $u.'@'.$config{CREATEDOMAIN};

  $config{AVUSER} = $config{CREATEADMIN}
    if ($old eq $config{AVUSER});

  $config{AVDOMAIN} = $config{CREATEDOMAIN}
    if ($config{AVDOMAIN} eq $oldDomain);

  if ($old eq $config{SMTPDEST}) {
    $config{SMTPDEST} = $config{CREATEADMIN};
  }
  if ($old eq $config{SMTPSOURCE}) {
    $config{SMTPSOURCE} = $config{CREATEADMIN};
  }
  my ($spamUser, $spamDomain) = split ('@', $config{TRAINSASPAM});
  $config{TRAINSASPAM} = $spamUser.'@'.$config{CREATEDOMAIN}
    if ($spamDomain eq $oldDomain);

  my ($hamUser, $hamDomain) = split ('@', $config{TRAINSAHAM});
  $config{TRAINSAHAM} = $hamUser.'@'.$config{CREATEDOMAIN}
    if ($hamDomain eq $oldDomain);

  my ($virusUser, $virusDomain) = split ('@', $config{VIRUSQUARANTINE});
  $config{VIRUSQUARANTINE} = $virusUser.'@'.$config{CREATEDOMAIN}
    if ($virusDomain eq $oldDomain);

}

sub setLdapBaseDN {
  while (1) {
    print "Warning: Do not change this from the default value unless\n";
    print "you are absolutely sure you know what you are doing!\n\n";
    my $new =
      askNonBlank("Ldap base DN:",
        $config{ldap_dit_base_dn_config});
    if ($config{ldap_dit_base_dn_config} ne $new) {
      $config{ldap_dit_base_dn_config} = $new;
    }
    return;
  }
}

sub setNotebookAccount {
  while (1) {
    my $new =
      ask("Global Documents account:",
        $config{NOTEBOOKACCOUNT});
    my ($u,$d) = split ('@', $new);
    my ($adminUser,$adminDomain) = split('@', $config{CREATEADMIN});
    if ($d ne $config{CREATEDOMAIN} && $d ne $adminDomain) {
      if ($config{CREATEDOMAIN} eq $adminDomain) {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN}\n" );
      } else {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN} or $adminDomain\n" );
      }
    } else {
      $config{NOTEBOOKACCOUNT} = $new;
      last;
    }
  }
}

sub setTrainSASpam {
  while (1) {

    my $new = ask("Spam training user:", $config{TRAINSASPAM});

    my ($u,$d) = split ('@', $new);
    my ($adminUser,$adminDomain) = split('@', $config{CREATEADMIN});
    if ($d ne $config{CREATEDOMAIN} && $d ne $adminDomain) {
      if ($config{CREATEDOMAIN} eq $adminDomain) {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN}\n" );
      } else {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN} or $adminDomain\n" );
      }
    } else {
      $config{TRAINSASPAM} = $new;
      last;
    }
  }
}

sub setTrainSAHam {
  while (1) {
    my $new =
      ask("Ham training user:",
        $config{TRAINSAHAM});
    my ($u,$d) = split ('@', $new);
    my ($adminUser,$adminDomain) = split('@', $config{CREATEADMIN});
    if ($d ne $config{CREATEDOMAIN} && $d ne $adminDomain) {
      if ($config{CREATEDOMAIN} eq $adminDomain) {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN}\n" );
      } else {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN} or $adminDomain\n" );
      }
    } else {
      $config{TRAINSAHAM} = $new;
      last;
    }
  }
}

sub setAmavisVirusQuarantine{
  while (1) {
    my $new =
      ask("Anti-virus quarantine user:",
        $config{VIRUSQUARANTINE});
    my ($u,$d) = split ('@', $new);
    my ($adminUser,$adminDomain) = split('@', $config{CREATEADMIN});
    if ($d ne $config{CREATEDOMAIN} && $d ne $adminDomain) {
      if ($config{CREATEDOMAIN} eq $adminDomain) {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN}\n" );
      } else {
        progress ( "You must create the user under the domain $config{CREATEDOMAIN} or $adminDomain\n" );
      }
    } else {
      $config{VIRUSQUARANTINE} = $new;
      last;
    }
  }
}

sub setMasterDNSIP {
  while (1) {
    my $new =
      ask("IP Address(es) of Master DNS Server(s), space separated:", $config{zimbraDNSMasterIP});
    my @IPs = split (' ', $new);
    unless(!validIPAddress(@IPs)) {
      progress("Supplied IP address(es) must be valid\n");
      next;
    }
    $config{zimbraDNSMasterIP} = $new;
    last;
  }
}

sub setCreateAdmin {

  while (1) {
    my $new =
      ask("Create admin user:", $config{CREATEADMIN});
    my ($u,$d) = split ('@', $new);

    unless(validEmailAddress($new)) {
      progress ( "Admin user must be a valid email account [$u\@$config{CREATEDOMAIN}]\n");
      next;
    }

    # spam/ham/quanrantine accounts follow admin domain if ldap isn't install
    # this prevents us from trying to provision in a non-existent domain
    if (!isEnabled("carbonio-directory-server")) {
      my ($spamUser, $spamDomain) = split ('@', $config{TRAINSASPAM});
      my ($hamUser, $hamDomain) = split ('@', $config{TRAINSAHAM});
      my ($virusUser, $virusDomain) = split ('@', $config{VIRUSQUARANTINE});
      $config{CREATEDOMAIN} = $d
        if ($config{CREATEDOMAIN} ne $d);

      $config{TRAINSASPAM} = $spamUser.'@'.$d
        if ($spamDomain ne $d);

      $config{TRAINSAHAM} = $hamUser.'@'.$d
        if ($hamDomain ne $d);

      $config{VIRUSQUARANTINE} = $virusUser.'@'.$d
        if ($virusDomain ne $d);

      $config{AVDOMAIN} = $d
        if ($config{AVDOMAIN} ne $d);
    }

    if ($config{CREATEADMIN} eq $config{AVUSER}) {
      $config{AVUSER} = $new;
    }
    if ($config{CREATEADMIN} eq $config{SMTPDEST}) {
      $config{SMTPDEST} = $new;
    }
    if ($config{CREATEADMIN} eq $config{SMTPSOURCE}) {
      $config{SMTPSOURCE} = $new;
    }
    $config{CREATEADMIN} = $new;
    last;
  }
}

sub removeUnusedWebapps {
  my $webAppsDir = "/opt/zextras/jetty/webapps";
  if ($config{SERVICEWEBAPP} eq "no") {
    system("rm -rf $webAppsDir/service")
      if (-d "$webAppsDir/service");
  }
  if ($config{UIWEBAPPS} eq "no") {
    system("rm -rf $webAppsDir/zimbra")
      if (-d "$webAppsDir/zimbra");
    system("rm -rf $webAppsDir/zimbraAdmin")
      if (-d "$webAppsDir/zimbraAdmin");
  }
  defineInstallWebapps();
  getInstalledWebapps();
}

sub validEmailAddress {
   return($_[0] =~ m/^[^@]+@([-\w]+\.)+[A-Za-z]{2,4}/ ? 1 : 0);
}

sub validIPAddress {
  my $rc = 0;
  foreach my $ip (@_) {
    chomp($ip);
    my $testip = NetAddr::IP->new($ip);
    if (ref($testip) ne 'NetAddr::IP') {
      $rc = 1;
    }
  }
  return $rc;
}

sub setLdapRootPass {
  while (1) {
    my $new =
      askPassword("Password for ldap root user (min 6 characters):",
        $config{LDAPROOTPASS});
    if (length($new) >= 6) {
      if ($config{LDAPROOTPASS} ne $new) {
        $config{LDAPROOTPASS} = $new;
        $ldapRootPassChanged = 1;
      }
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setLdapAdminPass {
  while (1) {
    my $new =
      askPassword("Password for ldap admin user (min 6 characters):",
        $config{LDAPADMINPASS});
    if (length($new) >= 6) {
      if ($config{LDAPADMINPASS} ne $new) {
        $config{LDAPADMINPASS} = $new;
        $ldapAdminPassChanged = 1;
      }
      ldapIsAvailable() if ($config{HOSTNAME} ne $config{LDAPHOST});
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setLdapRepPass {
  while (1) {
    my $new =
      askPassword("Password for ldap replication user (min 6 characters):",
        $config{LDAPREPPASS});
    if (length($new) >= 6) {
      if ($config{LDAPREPPASS} ne $new) {
        $config{LDAPREPPASS} = $new;
        $ldapRepChanged = 1;
      }
      ldapIsAvailable() if ($config{HOSTNAME} ne $config{LDAPHOST});
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setLdapPostPass {
  while (1) {
    my $new =
      askPassword("Password for ldap Postfix user (min 6 characters):",
        $config{LDAPPOSTPASS});
    if (length($new) >= 6) {
      if ($config{LDAPPOSTPASS} ne $new) {
        $config{LDAPPOSTPASS} = $new;
        $ldapPostChanged = 1;
      }
      ldapIsAvailable() if ($config{HOSTNAME} ne $config{LDAPHOST});
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setLdapAmavisPass {
  while (1) {
    my $new =
      askPassword("Password for ldap Amavis user (min 6 characters):",
        $config{LDAPAMAVISPASS});
    if (length($new) >= 6) {
      if ($config{LDAPAMAVISPASS} ne $new) {
        $config{LDAPAMAVISPASS} = $new;
        $ldapAmavisChanged = 1;
      }
      ldapIsAvailable() if ($config{HOSTNAME} ne $config{LDAPHOST});
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setLdapNginxPass {
  while (1) {
    my $new =
      askPassword("Password for ldap Nginx user (min 6 characters):",
        $config{ldap_nginx_password});
    if (length($new) >= 6) {
      if ($config{ldap_nginx_password} ne $new) {
        $config{ldap_nginx_password} = $new;
        $ldapNginxChanged = 1;
      }
      ldapIsAvailable() if ($config{HOSTNAME} ne $config{LDAPHOST});
      return;
    } else {
      print "Minimum length of 6 characters!\n";
    }
  }
}

sub setSmtpSource {
  $config{SMTPSOURCE} =
    askNonBlank("SMTP Source address:",
      $config{SMTPSOURCE});
}

sub setSmtpDest {
  $config{SMTPDEST} =
    askNonBlank("SMTP Destination address:",
      $config{SMTPDEST});
}

sub setAvUser {
  $config{AVUSER} =
    askNonBlank("Notification address for AV alerts:",
      $config{AVUSER});
  (undef, $config{AVDOMAIN}) = (split ('@',$config{AVUSER}))[1];
}

sub toggleYN {
  my $key = shift;
  $config{$key} = ($config{$key} eq "yes")?"no":"yes";
}
sub toggleTF {
  my $key = shift;
  $config{$key} = ($config{$key} eq "TRUE")?"FALSE":"TRUE";
  if ($key eq "MAILPROXY") {
    &toggleMailProxy();
  }
  if ($key eq "HTTPPROXY") {
    &toggleWebProxy();
  }
}

sub toggleSERVICEWEBAPP {
    my $key = shift;
    $config{SERVICEWEBAPP} = ($config{SERVICEWEBAPP} eq "yes")?"no":"yes";
}

sub toggleConfigEnabled {
  my $key = shift;
  $config{$key} = ($config{$key} eq "Enabled")?"Disabled":"Enabled";
}

sub toggleMailProxy() {
  if ($config{MAILPROXY} eq "TRUE") {
    $config{IMAPPORT} = 7143;
    $config{IMAPSSLPORT} = 7993;
    $config{POPPORT} = 7110;
    $config{POPSSLPORT} = 7995;
    $config{IMAPPROXYPORT} = 143;
    $config{IMAPSSLPROXYPORT} = 993;
    $config{POPPROXYPORT} = 110;
    $config{POPSSLPROXYPORT} = 995;
  } else {
    $config{IMAPPORT} = 143;
    $config{IMAPSSLPORT} = 993;
    $config{POPPORT} = 110;
    $config{POPSSLPORT} = 995;
    $config{IMAPPROXYPORT} = 7143;
    $config{IMAPSSLPROXYPORT} = 7993;
    $config{POPPROXYPORT} = 7110;
    $config{POPSSLPROXYPORT} = 7995;
  }
}

sub toggleWebProxy() {
  if ($config{HTTPPROXY} eq "TRUE") {
    $config{HTTPPORT} = 8080;
    $config{HTTPSPORT} = 8443;
    $config{HTTPPROXYPORT} = 80;
    $config{HTTPSPROXYPORT} = 443;
  } else {
    $config{HTTPPORT} = 80;
    $config{HTTPSPORT} = 443;
    $config{HTTPPROXYPORT} = 8080;
    $config{HTTPSPROXYPORT} = 8443;
  }
}

sub setUseProxy {

   if (isEnabled("carbonio-proxy")) {
      if ($config{MAILPROXY} eq "TRUE") {
         if ($config{IMAPPROXYPORT} == $config{IMAPPORT}) {
             $config{IMAPPORT} = 7000+$config{IMAPPROXYPORT};
         }
         if ($config{IMAPPORT}+7000 == $config{IMAPPROXYPORT}) {
             $config{IMAPPORT} = $config{IMAPPROXYPORT};
             $config{IMAPPROXYPORT} = $config{IMAPPROXYPORT}-7000;
         }
         if ($config{IMAPSSLPROXYPORT} == $config{IMAPSSLPORT}) {
             $config{IMAPSSLPORT} = 7000+$config{IMAPSSLPROXYPORT};
         }
         if ($config{IMAPSSLPORT}+7000 == $config{IMAPSSLPROXYPORT}) {
             $config{IMAPSSLPORT} = $config{IMAPSSLPROXYPORT};
             $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPROXYPORT}-7000;
         }
         if ($config{POPPROXYPORT} == $config{POPPORT}) {
             $config{POPPORT} = 7000+$config{POPPROXYPORT};
         }
         if ($config{POPPORT}+7000 == $config{POPPROXYPORT}) {
             $config{POPPORT} = $config{POPPROXYPORT};
             $config{POPPROXYPORT} = $config{POPPROXYPORT}-7000;
         }
         if ($config{POPSSLPROXYPORT} == $config{POPSSLPORT}) {
             $config{POPSSLPORT} = 7000+$config{POPSSLPROXYPORT};
         }
         if ($config{POPSSLPORT}+7000 == $config{POPSSLPROXYPORT}) {
             $config{POPSSLPORT} = $config{POPSSLPROXYPORT};
             $config{POPSSLPROXYPORT} = $config{POPSSLPROXYPORT}-7000;
         }
      } else {
         if ($config{IMAPPROXYPORT}+7000 == $config{IMAPPORT}) {
             $config{IMAPPORT} = $config{IMAPPROXYPORT};
             $config{IMAPPROXYPORT} = $config{IMAPPROXYPORT}+7000;
         }
         if ($config{IMAPSSLPROXYPORT}+7000 == $config{IMAPSSLPORT}) {
             $config{IMAPSSLPORT} = $config{IMAPSSLPROXYPORT};
             $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPROXYPORT} + 7000;
         }
         if ($config{POPPROXYPORT}+7000 == $config{POPPORT}) {
             $config{POPPORT} = $config{POPPROXYPORT};
             $config{POPPROXYPORT} = $config{POPPROXYPORT} + 7000;
         }
         if ($config{POPSSLPROXYPORT}+7000 == $config{POPSSLPORT}) {
             $config{POPSSLPORT} = $config{POPSSLPROXYPORT};
             $config{POPSSLPROXYPORT} = $config{POPSSLPROXYPORT}+7000;
         }
      }
      if ($config{HTTPPROXY} eq "TRUE") {
         if ($config{HTTPROXYPPORT} == $config{HTTPPORT}) {
             $config{HTTPPORT} = 8000+$config{HTTPPROXYPORT};
         }
         if ($config{HTTPPORT}+8000 == $config{HTTPPROXYPORT}) {
             $config{HTTPPORT} = $config{HTTPPROXYPORT};
             $config{HTTPPROXYPORT} = $config{HTTPPORT} - 8000;
         }
         if ($config{HTTPSPROXYPORT} == $config{HTTPSPORT}) {
             $config{HTTPSPORT} = 8000+$config{HTTPSPROXYPORT};
         }
         if ($config{HTTPSPORT}+8000 == $config{HTTPSPROXYPORT}) {
             $config{HTTPSPORT} = $config{HTTPSPROXYPORT};
             $config{HTTPSPROXYPORT} = $config{HTTPSPORT} - 8000;
         }
      } else {
         if ($config{HTTPPROXYPORT}+8000 == $config{HTTPPORT}) {
             $config{HTTPPORT} = $config{HTTPPROXYPORT};
             $config{HTTPPROXYPORT} = $config{HTTPPORT}+8000;
         }
         if ($config{HTTPSPROXYPORT}+8000 == $config{HTTPSPORT}) {
             $config{HTTPSPORT} = $config{HTTPSPROXYPORT};
             $config{HTTPSPROXYPORT} = $config{HTTPSPORT}+8000;
         }
      }
   } else {
      if (!isInstalled("carbonio-appserver")) {
         if ($config{IMAPPROXYPORT}+7000 == $config{IMAPPORT}) {
             $config{IMAPPORT} = $config{IMAPPROXYPORT};
             $config{IMAPPROXYPORT} = $config{IMAPPROXYPORT}+7000;
         }
         if ($config{IMAPSSLPROXYPORT}+7000 == $config{IMAPSSLPORT}) {
             $config{IMAPSSLPORT} = $config{IMAPSSLPROXYPORT};
             $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPROXYPORT} + 7000;
         }
         if ($config{POPPROXYPORT}+7000 == $config{POPPORT}) {
             $config{POPPORT} = $config{POPPROXYPORT};
              $config{POPPROXYPORT} = $config{POPPROXYPORT} + 7000;
         }
         if ($config{POPSSLPROXYPORT}+7000 == $config{POPSSLPORT}) {
             $config{POPSSLPORT} = $config{POPSSLPROXYPORT};
             $config{POPSSLPROXYPORT} = $config{POPSSLPROXYPORT}+7000;
         }
         if ($config{HTTPPROXYPORT}+8000 == $config{HTTPPORT}) {
             $config{HTTPPORT} = $config{HTTPPROXYPORT};
             $config{HTTPPROXYPORT} = $config{HTTPPORT}+8000;
         }
         if ($config{HTTPSPROXYPORT}+8000 == $config{HTTPSPORT}) {
             $config{HTTPSPORT} = $config{HTTPSPROXYPORT};
             $config{HTTPSPROXYPORT} = $config{HTTPSPORT}+8000;
         }
      } else {
         if ($config{"zimbraMailProxy"} eq "TRUE") {
            if ($config{IMAPPROXYPORT} == $config{IMAPPORT}) {
                $config{IMAPPORT} = 7000+$config{IMAPPROXYPORT};
            }
            if ($config{IMAPPORT}+7000 == $config{IMAPPROXYPORT}) {
                $config{IMAPPORT} = $config{IMAPPROXYPORT};
                $config{IMAPPROXYPORT} = $config{IMAPPROXYPORT}-7000;
            }
            if ($config{IMAPSSLPROXYPORT} == $config{IMAPSSLPORT}) {
                $config{IMAPSSLPORT} = 7000+$config{IMAPSSLPROXYPORT};
            }
            if ($config{IMAPSSLPORT}+7000 == $config{IMAPSSLPROXYPORT}) {
                $config{IMAPSSLPORT} = $config{IMAPSSLPROXYPORT};
                $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPROXYPORT}-7000;
            }
            if ($config{POPPROXYPORT} == $config{POPPORT}) {
                $config{POPPORT} = 7000+$config{POPPROXYPORT};
            }
            if ($config{POPPORT}+7000 == $config{POPPROXYPORT}) {
                $config{POPPORT} = $config{POPPROXYPORT};
                $config{POPPROXYPORT} = $config{POPPROXYPORT}-7000;
            }
            if ($config{POPSSLPROXYPORT} == $config{POPSSLPORT}) {
                $config{POPSSLPORT} = 7000+$config{POPSSLPROXYPORT};
            }
            if ($config{POPSSLPORT}+7000 == $config{POPSSLPROXYPORT}) {
                $config{POPSSLPORT} = $config{POPSSLPROXYPORT};
                $config{POPSSLPROXYPORT} = $config{POPSSLPROXYPORT}-7000;
            }
         }
         if ($config{"zimbraWebProxy"} eq "TRUE") {
            if ($config{HTTPROXYPPORT} == $config{HTTPPORT}) {
                $config{HTTPPORT} = 8000+$config{HTTPPROXYPORT};
            }
            if ($config{HTTPPORT}+8000 == $config{HTTPPROXYPORT}) {
                $config{HTTPPORT} = $config{HTTPPROXYPORT};
                $config{HTTPPROXYPORT} = $config{HTTPPORT} - 8000;
            }
            if ($config{HTTPSPROXYPORT} == $config{HTTPSPORT}) {
                $config{HTTPSPORT} = 8000+$config{HTTPSPROXYPORT};
            }
            if ($config{HTTPSPORT}+8000 == $config{HTTPSPROXYPORT}) {
                $config{HTTPSPORT} = $config{HTTPSPROXYPORT};
                $config{HTTPSPROXYPORT} = $config{HTTPSPORT} - 8000;
            }
         }
      }
   }
}

sub setStoreMode {
  while (1) {
    my $m =
      askNonBlank("Please enter the web server mode (http,https,both,mixed,redirect)",
        $config{MODE});
    if (isInstalled("carbonio-proxy")) {
      if ($config{zimbra_require_interprocess_security}) {
        if ($m eq "https" || $m eq "both" ) {
          $config{MODE} = $m;
          return;
        } else {
          print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
        }
      } else {
        if ($m eq "http" || $m eq "both" ) {
          $config{MODE} = $m;
          return;
        } else {
          print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
        }
      }
    } else {
      my @proxytargets;
      open(ZMPROV, "$ZMPROV gas proxy 2>/dev/null|");
      chomp(@proxytargets = <ZMPROV>);
      close(ZMPROV);
      if (scalar @proxytargets) {
        if ($config{zimbra_require_interprocess_security}) {
          if ($m eq "https" || $m eq "both" ) {
            $config{MODE} = $m;
            return;
          } else {
            print qq(Only "https" and "both" are valid modes when requiring interprocess security with web proxy.\n);
          }
        } else {
          if ($m eq "http" || $m eq "both" ) {
            $config{MODE} = $m;
            return;
          } else {
            print qq(Only "http" and "both" are valid modes when not requiring interprocess security with web proxy.\n);
          }
        }
      } else {
        if ($m eq "http" || $m eq "https" || $m eq "mixed" || $m eq "both" || $m eq "redirect" ) {
          $config{MODE} = $m;
          return;
        }
      }
    }
    print "Please enter a valid mode!\n";
  }
}

sub setProxyMode {
  while (1) {
    my $m =
      askNonBlank("Please enter the proxy server mode (http,https,both,mixed,redirect)",
        $config{PROXYMODE});
    if ($config{zimbra_require_interprocess_security}) {
      if ($m eq "https" || $m eq "redirect") {
        $config{PROXYMODE} = $m;
        return;
      } else {
        print qq(Only "https" and "redirect" are valid modes when requiring interprocess security with web proxy.\n);
      }
    } else {
      if ($m eq "http" || $m eq "https" || $m eq "mixed" || $m eq "both" || $m eq "redirect" ) {
        $config{PROXYMODE} = $m;
        return;
      }
    }
    print "Please enter a valid mode!\n";
  }
}

sub changeLdapHost {
  $config{LDAPHOST} = shift;
  $config{LDAPHOST} = lc($config{LDAPHOST});
  if (isInstalled("carbonio-directory-server") && $config{LDAPHOST} eq "") {
      $ldapReplica=0;
      $config{LDAPREPLICATIONTYPE}="master";
  } elsif (isInstalled("carbonio-directory-server") && $config{LDAPHOST} ne $config{HOSTNAME}) {
      $ldapReplica=1;
      $config{LDAPREPLICATIONTYPE}="replica";
  } elsif (isInstalled("carbonio-directory-server") && $config{LDAPHOST} eq $config{HOSTNAME}) {
      $ldapReplica=0;
      $config{LDAPREPLICATIONTYPE}="master";
  }
}

sub changeLdapPort {
  $config{LDAPPORT} = shift;
}

sub changeLdapServerID {
  $config{LDAPSERVERID} = shift;
}

sub getDnsRecords {
  my $name = shift;
  my $qtype = shift;

  my $res = Net::DNS::Resolver->new;
  my @servers = $res->nameservers();
  my $ans = $res->search ($name, $qtype);

  return $ans;
}

sub lookupHostName {
  my $name = shift;
  my $qtype = shift;

  my $res = Net::DNS::Resolver->new;
  my @servers = $res->nameservers();
  my $ans = $res->search ($name, $qtype);
  if (!defined ($ans)) {
    progress ("No results returned for $qtype lookup of $name\n");
    progress ("Checked nameservers:\n");
    foreach (@servers) {
      progress ("\t$_\n");
    }
    return 1;
  } else {
    #progress ("Received answer:\n");
    #progress ($ans->string()."\n");
    return 0;
  }
}

sub setHostName {
  my $old = $config{HOSTNAME};
  while (1) {
    $config{HOSTNAME} =
      askNonBlank("Please enter the logical hostname for this host",
        $config{HOSTNAME});
    if (lookupHostName ($config{HOSTNAME}, 'A')) {
      progress("\n\nDNS ERROR resolving $config{HOSTNAME}\n");
      progress("It is suggested that the hostname be resolvable via DNS\n");
      if (askYN("Re-Enter hostname","Yes") eq "no") {
        last;
      }
      $config{HOSTNAME} = $old;
    } else {last;}
  }
  $config{HOSTNAME} = lc($config{HOSTNAME});
  if ($config{SMTPHOST} eq $old) {
    $config{SMTPHOST} = $config{HOSTNAME};
  }
  if ($config{LDAPHOST} eq $old) {
    changeLdapHost($config{HOSTNAME});
  }
  if ($config{CREATEDOMAIN} eq $old) {
    $config{CREATEDOMAIN} = $config{HOSTNAME};

    my ($u,$d) = split ('@', $config{CREATEADMIN});
    $config{CREATEADMIN} = $u.'@'.$config{CREATEDOMAIN};

    my ($u,$d) = split ('@', $config{AVUSER});
    $config{AVUSER} = $u.'@'.$config{CREATEDOMAIN};

    $config{AVDOMAIN} = $config{CREATEDOMAIN};

    my ($u,$d) = split ('@', $config{TRAINSASPAM});
    $config{TRAINSASPAM} = $u.'@'.$config{CREATEDOMAIN};

    my ($u,$d) = split ('@', $config{TRAINSAHAM});
    $config{TRAINSAHAM} = $u.'@'.$config{CREATEDOMAIN};

    my ($u,$d) = split ('@', $config{VIRUSQUARANTINE});
    $config{VIRUSQUARANTINE} = $u.'@'.$config{CREATEDOMAIN};

  }
  my ($suser,$sdomain) = split ('@', $config{SMTPSOURCE}, 2);
  if ($sdomain eq $old) {
    $config{SMTPSOURCE} = $suser.'@'.$config{CREATEDOMAIN};
  }
  ($suser,$sdomain) = split ('@', $config{SMTPDEST}, 2);
  if ($sdomain eq $old) {
    $config{SMTPDEST} = $suser.'@'.$config{CREATEDOMAIN};
  }
}

sub setSmtpHost {
  $config{SMTPHOST} =
    askNonBlank("Please enter the SMTP server hostname:",
      $config{SMTPHOST});
}

sub setLdapHost {
  changeLdapHost( askNonBlank("Please enter the ldap server hostname:",
      $config{LDAPHOST}));
}

sub setLdapPort {
  changeLdapPort( askNum("Please enter the ldap server port:",
      $config{LDAPPORT}));
}

sub setLdapServerID {
  changeLdapServerID(askPositiveInt("Please enter the ldap Server ID:", $config{LDAPSERVERID}));
}

sub setLdapReplicationType {
  while (1) {
    my $m =
      askNonBlank("Please enter the LDAP replication type (replica, mmr)",
        $config{LDAPREPLICATIONTYPE});
    if ($m eq "replica" || $m eq "mmr") {
      $config{LDAPREPLICATIONTYPE} = $m;
      return;
    }
    print "Please enter a valid replication type!\n";
  }
}

sub setHttpPort {
  $config{HTTPPORT} = askNum("Please enter the HTTP server port:",
      $config{HTTPPORT});

  if($config{HTTPPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{HTTPPORT} == $config{HTTPPROXYPORT}) {
      $config{HTTPPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{HTTPPORT} == $config{HTTPPROXYPORT}) {
      if ($config{HTTPPORT} > 8000) {
        $config{HTTPPROXYPORT} = $config{HTTPPORT} - 8000;
      } else {
        $config{HTTPPROXYPORT} = $config{HTTPPORT} + 8000;
      }
    }
  }
}

sub setHttpsPort {
  $config{HTTPSPORT} = askNum("Please enter the HTTPS server port:",
      $config{HTTPSPORT});

  if($config{HTTPPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{HTTPSPORT} == $config{HTTPSPROXYPORT}) {
      $config{HTTPSPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{HTTPSPORT} == $config{HTTPSPROXYPORT}) {
      if ($config{HTTPSPORT} > 8000) {
        $config{HTTPSPROXYPORT} = $config{HTTPSPORT} - 8000;
      } else {
        $config{HTTPSPROXYPORT} = $config{HTTPSPORT} + 8000;
      }
    }
  }
}

sub setImapPort {
  $config{IMAPPORT} = askNum("Please enter the IMAP server port:",
      $config{IMAPPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{IMAPPORT} == $config{IMAPPROXYPORT}) {
      $config{IMAPPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{IMAPPORT} == $config{IMAPPROXYPORT}) {
      if ($config{IMAPPORT} > 7000) {
        $config{IMAPPROXYPORT} = $config{IMAPPORT} - 7000;
      } else {
        $config{IMAPPROXYPORT} = $config{IMAPPORT} + 7000;
      }
    }
  }
}

sub setImapSSLPort {
  $config{IMAPSSLPORT} = askNum("Please enter the IMAP SSL server port:",
      $config{IMAPSSLPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT}) {
      $config{IMAPSSLPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{IMAPSSLPORT} == $config{IMAPSSLPROXYPORT}) {
      if ($config{IMAPSSLPORT} > 7000) {
        $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPORT} - 7000;
      } else {
        $config{IMAPSSLPROXYPORT} = $config{IMAPSSLPORT} + 7000;
      }
    }
  }
}

sub setPopPort {
  $config{POPPORT} = askNum("Please enter the POP server port:",
      $config{POPPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{POPPORT} == $config{POPPROXYPORT}) {
      $config{POPPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{POPPORT} == $config{POPPROXYPORT}) {
      if ($config{POPPORT} > 7000) {
        $config{POPPROXYPORT} = $config{POPPORT} - 7000;
      } else {
        $config{POPPROXYPORT} = $config{POPPORT} + 7000;
      }
    }
  }
}

sub setPopSSLPort {
  $config{POPSSLPORT} = askNum("Please enter the POP SSL server port:",
      $config{POPSSLPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{POPSSLPORT} == $config{POPSSLPROXYPORT}) {
      $config{POPSSLPROXYPORT}="UNSET";
    }
  } elsif (isInstalled("carbonio-appserver") && !isInstalled("carbonio-proxy")) {
    if($config{POPSSLPORT} == $config{POPSSLPROXYPORT}) {
      if ($config{POPSSLPORT} > 7000) {
        $config{POPSSLPROXYPORT} = $config{POPSSLPORT} - 7000;
      } else {
        $config{POPSSLPROXYPORT} = $config{POPSSLPORT} + 7000;
      }
    }
  }
}

sub setImapProxyPort {
  $config{IMAPPROXYPORT} = askNum("Please enter the IMAP Proxy server port:",
      $config{IMAPPROXYPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{IMAPPROXYPORT} == $config{IMAPPORT}) {
      $config{IMAPPORT}="UNSET";
    }
  }
}
sub setImapSSLProxyPort {
  $config{IMAPSSLPROXYPORT} = askNum("Please enter the IMAP SSL Proxy server port:",
      $config{IMAPSSLPROXYPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{IMAPSSLPROXYPORT} == $config{IMAPSSLPORT}) {
      $config{IMAPSSLPORT}="UNSET";
    }
  }
}
sub setPopProxyPort {
  $config{POPPROXYPORT} = askNum("Please enter the POP Proxy server port:",
      $config{POPPROXYPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{POPPROXYPORT} == $config{POPPORT}) {
      $config{POPPORT}="UNSET";
    }
  }
}
sub setPopSSLProxyPort {
  $config{POPSSLPROXYPORT} = askNum("Please enter the POP SSL Proxyserver port:",
      $config{POPSSLPROXYPORT});

  if($config{MAILPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{POPSSLPROXYPORT} == $config{POPSSLPORT}) {
      $config{POPSSLPORT}="UNSET";
    }
  }
}

sub setHttpProxyPort {
  $config{HTTPPROXYPORT} = askNum("Please enter the HTTP Proxyserver port:",
      $config{HTTPPROXYPORT});

  if($config{HTTPPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{HTTPPROXYPORT} == $config{HTTPPORT}) {
      $config{HTTPPORT}="UNSET";
    }
  }
}

sub setHttpsProxyPort {
  $config{HTTPSPROXYPORT} = askNum("Please enter the HTTPS Proxyserver port:",
      $config{HTTPSPROXYPORT});

  if($config{HTTPPROXY} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE") {
    if($config{HTTPSPROXYPORT} == $config{HTTPSPORT}) {
      $config{HTTPSPORT}="UNSET";
    }
  }
}

sub setTimeZone {
  my $timezones="/opt/zextras/conf/timezones.ics";
  if (-f $timezones) {
    detail("Loading default list of timezones.\n");
    my $tz = new Zimbra::Util::Timezone;
    $tz->parse;

    my $new;

    # build a hash of the timezone objects with a unique number as the value
    my %TZID = undef;
    my $ctr=1;
    $TZID{$_} = $ctr++ foreach sort $tz->dump;
    my %RTZID = reverse %TZID;

    # get a reference to the default value or attempt to lookup the system locale.
    detail("Previous TimeZoneID $config{zimbraPrefTimeZoneId}\n");
    my $ltzref=$tz->gettzbyid("$config{zimbraPrefTimeZoneId}");
    unless (defined $ltzref) {
      detail ("Determining system locale.\n");
      my $localtzname=qx(/bin/date '+%Z');
      chomp($localtzname);
      detail("DEBUG: Local tz name $localtzname\n");
      $ltzref=$tz->gettzbyname($localtzname);
    }

    # look up the current value and present a list
    my $default = $TZID{$ltzref->tzid} || "21";
    while ($new eq "") {
      foreach (sort {$TZID{$a} <=> $TZID{$b}} keys %TZID) {
        print "$TZID{$_} $_\n";
      }
      my $ans=askNum("Enter the number for the local timezone:", $default);
      $new = $RTZID{$ans};
    }
    $config{zimbraPrefTimeZoneId} = $new;
  }
}

sub setIPMode {
  while (1) {
    my $new =
      askPassword("IP Mode for Zimbra (ipv4, both, ipv6):",
        $config{zimbraIPMode});
    if ($new eq "ipv4" ||  $new eq "both" || $new eq "ipv6") {
      if ($config{zimbraIPMode} ne $new) {
        $config{zimbraIPMode} = $new;
      }
      return;
    } else {
      print "IP Mode must be one of ipv4, both, or ipv6!\n";
    }
  }
}

sub setSSLDefaultDigest {
  while (1) {
    my $new =
      askPassword("Default OpenSSL digest:",
        $config{ssl_default_digest});
    my $ssl_digests= join(' ', @ssl_digests);
    if ($ssl_digests =~ /\b$new\b/) {
      if ($config{ssl_default_digest} ne $new) {
        $config{ssl_default_digest} = $new;
      }
      return;
    } else {
      print "Valid digest modes are: $ssl_digests!\n";
    }
  }
}

sub setEnabledDependencies {
  if (isEnabled("carbonio-directory-server")) {
    if ($config{LDAPHOST} eq "") {
      changeLdapHost($config{HOSTNAME});
    }
  } else {
    if ($config{LDAPHOST} eq $config{HOSTNAME}) {
      changeLdapHost("");
      $config{LDAPADMINPASS} = "";
      $config{LDAPROOTPASS} = "";
    }
  }

  if (isEnabled("carbonio-appserver")) {
    if (isEnabled("carbonio-mta")) {
      $config{SMTPHOST} = $config{HOSTNAME};
    }
    if ($config{"zimbraMailProxy"} eq "TRUE" || $config{"zimbraWebProxy"} eq "TRUE") {
     setUseProxy();
    }
  }

  if (isEnabled("carbonio-mta")) {
    if ($newinstall) {
      $config{RUNAV} = "yes";
      $config{RUNSA} = "yes";
      $config{RUNDKIM} = "yes";
      $config{RUNCBPOLICYD} = "no";
    } else {
      $config{RUNSA} = (isServiceEnabled("antispam") ? "yes" : "no");
      $config{RUNAV} = (isServiceEnabled("antivirus") ? "yes" : "no");
      if ($config{RUNDKIM} ne "yes") {
        $config{RUNDKIM} = (isServiceEnabled("opendkim") ? "yes" : "no");
      }
      $config{RUNCBPOLICYD} = (isServiceEnabled("cbpolicyd") ? "yes" : "no");
    }
  }
  if (isInstalled("carbonio-proxy")) {
     setUseProxy();
  }
}

sub toggleEnabled {
  my $p = shift;
  $enabledPackages{$p} = (isEnabled($p))?"Disabled":"Enabled";
  setEnabledDependencies();
}

sub verifyQuit {
  if (askYN("Quit without applying changes?", "No") eq "yes") {return 1;}
  return 0;
}

sub genPackageMenu {
  my $package = shift;
  my %lm = ();
  $lm{menuitems}{1} = {
    "prompt" => "Status:",
    "var" => \$enabledPackages{$package},
    "callback" => \&toggleEnabled,
    "arg" => $package};
  $lm{promptitem} = {
    "selector" => "r",
    "prompt" => "Select, or 'r' for previous menu ",
    "action" => "return"};
  $lm{default} = "r";
  return \%lm;
}

sub genSubMenu {
  my %lm = ();
  $lm{promptitem} = {
    "selector" => "r",
    "prompt" => "Select, or 'r' for previous menu ",
    "action" => "return"};
  $lm{default} = "r";
  return \%lm;
}

sub isLdapMaster {
  return(($config{LDAPHOST} eq $config{HOSTNAME}) ? 1 : 0);
}

sub isZCS {
  return((grep(/\b\w+-appserver\b/,@packageList)) ? 1 : 0);
}

sub createPackageMenu {
  my $package = shift;
  if ($package eq "carbonio-directory-server") {
    return createLdapMenu($package);
  } elsif ($package eq "carbonio-mta") {
    return createMtaMenu($package);
  } elsif ($package eq "carbonio-appserver") {
    return createStoreMenu($package);
  } elsif ($package eq "carbonio-proxy") {
    return createProxyMenu($package);
  }
}

sub createCommonMenu {
  my $package = shift;
  my $lm = genSubMenu();

  $$lm{title} = "Common configuration";

  $$lm{createsub} = \&createCommonMenu;
  $$lm{createarg} = $package;

  my $i = 1;
  $$lm{menuitems}{$i} = {
    "prompt" => "Hostname:",
    "var" => \$config{HOSTNAME},
    "callback" => \&setHostName
    };
  $i++;
  $$lm{menuitems}{$i} = {
    "prompt" => "Ldap master host:",
    "var" => \$config{LDAPHOST},
    "callback" => \&setLdapHost
    };
  $i++;
  $$lm{menuitems}{$i} = {
    "prompt" => "Ldap port:",
    "var" => \$config{LDAPPORT},
    "callback" => \&setLdapPort
    };
  $i++;
  if ($config{LDAPADMINPASS} eq "") {
    $config{LDAPADMINPASSSET} = "UNSET";
  } else {
    $config{LDAPADMINPASSSET} = "set" unless ($config{LDAPADMINPASSSET} eq "Not Verified");
  }
  $$lm{menuitems}{$i} = {
    "prompt" => "Ldap Admin password:",
    "var" => \$config{LDAPADMINPASSSET},
    "callback" => \&setLdapAdminPass
    };
  $i++;
  # ldap users
  if (!defined($installedPackages{"carbonio-directory-server"})) {
    $$lm{menuitems}{$i} = {
      "prompt" => "LDAP Base DN:",
      "var" => \$config{ldap_dit_base_dn_config},
      "callback" => \&setLdapBaseDN,
      };
    $i++;
  }
  # interprocess security
  $$lm{menuitems}{$i} = {
    "prompt" => "Secure interprocess communications:",
    "var" => \$config{ZIMBRA_REQ_SECURITY},
    "callback" => \&toggleYN,
    "arg" => "ZIMBRA_REQ_SECURITY",
  };
  $i++;
  if ($config{ZIMBRA_REQ_SECURITY} eq "yes") {
     $config{zimbra_require_interprocess_security} = 1;
  } else {
     $config{zimbra_require_interprocess_security} = 0;
     $starttls=0;
  }
  $$lm{menuitems}{$i} = {
    "prompt" => "TimeZone:",
    "var" => \$config{zimbraPrefTimeZoneId},
    "callback" => \&setTimeZone
  };
  $i++;
  $$lm{menuitems}{$i} = {
    "prompt" => "IP Mode:",
    "var" => \$config{zimbraIPMode},
    "callback" => \&setIPMode
  };
  $i++;
  $$lm{menuitems}{$i} = {
    "prompt" => "Default SSL digest:",
    "var" => \$config{ssl_default_digest},
    "callback" => \&setSSLDefaultDigest
  };
  $i++;
  return $lm;
}

sub createLdapMenu {
  my $package = shift;
  my $lm = genPackageMenu($package);

  $$lm{title} = "Ldap configuration";

  $$lm{createsub} = \&createLdapMenu;
  $$lm{createarg} = $package;

  my $i = 2;
  if (isEnabled($package)) {
    $$lm{menuitems}{$i} = {
      "prompt" => "Create Domain:",
      "var" => \$config{DOCREATEDOMAIN},
      "callback" => \&toggleYN,
      "arg" => "DOCREATEDOMAIN",
      };
    $i++;
    if ($config{DOCREATEDOMAIN} eq "yes") {
      $$lm{menuitems}{$i} = {
        "prompt" => "Domain to create:",
        "var" => \$config{CREATEDOMAIN},
        "callback" => \&setCreateDomain,
        };
      $i++;
    }
    #$$lm{menuitems}{$i} = {
      #"prompt" => "Sync domain GALs to contact folders:",
      #"var" => \$config{ENABLEGALSYNCACCOUNTS},
      #"callback" => \&toggleYN,
      #"arg" => "ENABLEGALSYNCACCOUNTS",
      #};
    #$i++;
    if($config{LDAPREPLICATIONTYPE} ne "master") {
      $$lm{menuitems}{$i} = {
        "prompt" => "Ldap replication type:",
        "var" => \$config{LDAPREPLICATIONTYPE},
        "callback" => \&setLdapReplicationType
      };
      $i++;
    }
    if ($config{LDAPREPLICATIONTYPE} eq "mmr") {
      $$lm{menuitems}{$i} = {
        "prompt" => "Ldap Server ID:",
        "var" => \$config{LDAPSERVERID},
        "callback" => \&setLdapServerID
      };
      $i++;
    }
    if ($config{LDAPROOTPASS} ne "") {
      $config{LDAPROOTPASSSET} = "set";
    } else {
      $config{LDAPROOTPASSSET} = "UNSET" unless ($config{LDAPROOTPASSSET} eq "Not Verified");
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Ldap root password:",
      "var" => \$config{LDAPROOTPASSSET},
      "callback" => \&setLdapRootPass
      };
    $i++;
    if ($config{LDAPREPPASS} eq "") {
      $config{LDAPREPPASSSET} = "UNSET";
    } else {
      $config{LDAPREPPASSSET} = "set" unless ($config{LDAPREPPASSSET} eq "Not Verified");
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Ldap replication password:",
      "var" => \$config{LDAPREPPASSSET},
      "callback" => \&setLdapRepPass
      };
    $i++;
    if ($config{HOSTNAME} eq $config{LDAPHOST} || $config{LDAPREPLICATIONTYPE} ne "replica" || isEnabled("carbonio-mta")) {
      if ($config{LDAPPOSTPASS} eq "") {
        $config{LDAPPOSTPASSSET} = "UNSET";
      } else {
        $config{LDAPPOSTPASSSET} = "set" unless ($config{LDAPPOSTPASSSET} eq "Not Verified");
      }
      $$lm{menuitems}{$i} = {
        "prompt" => "Ldap postfix password:",
        "var" => \$config{LDAPPOSTPASSSET},
        "callback" => \&setLdapPostPass
        };
      $i++;
      if ($config{LDAPAMAVISPASS} eq "") {
        $config{LDAPAMAVISPASSSET} = "UNSET";
      } else {
        $config{LDAPAMAVISPASSSET} = "set" unless ($config{LDAPAMAVISPASSSET} eq "Not Verified");
      }
      $$lm{menuitems}{$i} = {
        "prompt" => "Ldap amavis password:",
        "var" => \$config{LDAPAMAVISPASSSET},
        "callback" => \&setLdapAmavisPass
        };
      $i++;
    }
    if ($config{HOSTNAME} eq $config{LDAPHOST} || $config{LDAPREPLICATIONTYPE} ne "replica" || isEnabled("carbonio-proxy")) {
      if ($config{ldap_nginx_password} eq "") {
        $config{LDAPNGINXPASSSET} = "UNSET";
      } else {
        $config{LDAPNGINXPASSSET} = "set" unless ($config{LDAPNGINXPASSSET} eq "Not Verified");
      }
      $$lm{menuitems}{$i} = {
        "prompt" => "Ldap nginx password:",
        "var" => \$config{LDAPNGINXPASSSET},
        "callback" => \&setLdapNginxPass
        };
      $i++;
    }
  }
  return $lm;
}

sub createLdapUsersMenu {
  my $package = shift;
  my $lm = genSubMenu();

  $$lm{title} = "Ldap Users configuration";

  $$lm{createsub} = \&createLdapUsersMenu;
  $$lm{createarg} = $package;

  my $i = 1;
  return $lm;
}

sub createMtaMenu {
  my $package = shift;
  my $lm = genPackageMenu($package);

  $$lm{title} = "Mta configuration";

  $$lm{createsub} = \&createMtaMenu;
  $$lm{createarg} = $package;

  my $i = 2;
  if (isEnabled($package)) {
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable Spamassassin:",
      "var" => \$config{RUNSA},
      "callback" => \&toggleYN,
      "arg" => "RUNSA",
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable Clam AV:",
      "var" => \$config{RUNAV},
      "callback" => \&toggleYN,
      "arg" => "RUNAV",
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable OpenDKIM:",
      "var" => \$config{RUNDKIM},
      "callback" => \&toggleYN,
      "arg" => "RUNDKIM",
      };
    $i++;
    if ($config{RUNAV} eq "yes") {
      $$lm{menuitems}{$i} = {
        "prompt" => "Notification address for AV alerts:",
        "var" => \$config{AVUSER},
        "callback" => \&setAvUser,
        };
      $i++;
    }
    if ($config{LDAPPOSTPASS} eq "") {
      $config{LDAPPOSTPASSSET} = "UNSET";
    } else {
      $config{LDAPPOSTPASSSET} = "set" unless ($config{LDAPPOSTPASSSET} eq "Not Verified");
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Bind password for postfix ldap user:",
      "var" => \$config{LDAPPOSTPASSSET},
      "callback" => \&setLdapPostPass
      };
    $i++;
    if ($config{LDAPAMAVISPASS} eq "") {
      $config{LDAPAMAVISPASSSET} = "UNSET";
    } else {
      $config{LDAPAMAVISPASSSET} = "set" unless ($config{LDAPAMAVISPASSSET} eq "Not Verified");
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Bind password for amavis ldap user:",
      "var" => \$config{LDAPAMAVISPASSSET},
      "callback" => \&setLdapAmavisPass
      };
    $i++;
  }
  return $lm;
}

sub createProxyMenu {
  my $package = shift;
  my $lm = genPackageMenu($package);

  $$lm{title} = "Proxy configuration";

  $$lm{createsub} = \&createProxyMenu;
  $$lm{createarg} = $package;

  my $i = 2;
  if (isInstalled($package)) {
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable POP/IMAP Proxy:",
      "var" => \$config{MAILPROXY},
      "callback" => \&toggleTF,
      "arg" => "MAILPROXY",
    };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable strict server name enforcement?",
      "var" => \$config{STRICTSERVERNAMEENABLED},
      "callback" => \&toggleYN,
      "arg" => "STRICTSERVERNAMEENABLED",
    };
    $i++;
    if($config{MAILPROXY} eq "TRUE") {
       if(!isEnabled("carbonio-appserver")) {
          $$lm{menuitems}{$i} = {
            "prompt" => "IMAP server port:",
            "var" => \$config{IMAPPORT},
            "callback" => \&setImapPort,
            };
          $i++;
          $$lm{menuitems}{$i} = {
            "prompt" => "IMAP server SSL port:",
            "var" => \$config{IMAPSSLPORT},
            "callback" => \&setImapSSLPort,
            };
          $i++;
       }
       $$lm{menuitems}{$i} = {
         "prompt" => "IMAP proxy port:",
         "var" => \$config{IMAPPROXYPORT},
         "callback" => \&setImapProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "IMAP SSL proxy port:",
         "var" => \$config{IMAPSSLPROXYPORT},
         "callback" => \&setImapSSLProxyPort,
       };
       $i++;
       if(!isEnabled("carbonio-appserver")) {
          $$lm{menuitems}{$i} = {
            "prompt" => "POP server port:",
            "var" => \$config{POPPORT},
            "callback" => \&setPopPort,
            };
          $i++;
          $$lm{menuitems}{$i} = {
            "prompt" => "POP server SSL port:",
            "var" => \$config{POPSSLPORT},
            "callback" => \&setPopSSLPort,
            };
          $i++;
       }
       $$lm{menuitems}{$i} = {
         "prompt" => "POP proxy port:",
         "var" => \$config{POPPROXYPORT},
         "callback" => \&setPopProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "POP SSL proxy port:",
         "var" => \$config{POPSSLPROXYPORT},
         "callback" => \&setPopSSLProxyPort,
       };
       $i++;
    }
    if ($config{HTTPPROXY} eq "TRUE" || $config{MAILPROXY} eq "TRUE") {
      if ($config{ldap_nginx_password} eq "") {
        $config{LDAPNGINXPASSSET} = "UNSET";
      } else {
        $config{LDAPNGINXPASSSET} = "set" unless ($config{LDAPNGINXPASSSET} eq "Not Verified");
      }
      $$lm{menuitems}{$i} = {
        "prompt" => "Bind password for nginx ldap user:",
        "var" => \$config{LDAPNGINXPASSSET},
        "callback" => \&setLdapNginxPass
      };
      $i++;
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Enable HTTP[S] Proxy:",
      "var" => \$config{HTTPPROXY},
      "callback" => \&toggleTF,
      "arg" => "HTTPPROXY",
    };
    $i++;
    if ($config{HTTPPROXY} eq "TRUE") {
       if(!isEnabled("carbonio-appserver")) {
          $$lm{menuitems}{$i} = {
            "prompt" => "Web server HTTP port:",
            "var" => \$config{HTTPPORT},
            "callback" => \&setHttpPort,
            };
          $i++;
          $$lm{menuitems}{$i} = {
            "prompt" => "Web server HTTPS port:",
            "var" => \$config{HTTPSPORT},
            "callback" => \&setHttpsPort,
            };
          $i++;
       }
       $$lm{menuitems}{$i} = {
         "prompt" => "HTTP proxy port:",
         "var" => \$config{HTTPPROXYPORT},
         "callback" => \&setHttpProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "HTTPS proxy port:",
         "var" => \$config{HTTPSPROXYPORT},
         "callback" => \&setHttpsProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "Proxy server mode:",
         "var" => \$config{PROXYMODE},
         "callback" => \&setProxyMode,
       };
       $i++;
    }
  }
  return $lm;
}

sub createStoreMenu {
  my $package = shift;
  my $lm = genPackageMenu($package);

  $$lm{title} = "Store configuration";

  $$lm{createsub} = \&createStoreMenu;
  $$lm{createarg} = $package;

  my $i = 2;
  if (isEnabled($package)) {
    $$lm{menuitems}{$i} = {
      "prompt" => "Create Admin User:",
      "var" => \$config{DOCREATEADMIN},
      "callback" => \&toggleYN,
      "arg" => "DOCREATEADMIN",
      };
    $i++;
    my $ldap_virusquarantine = getLdapConfigValue("zimbraAmavisQuarantineAccount")
      if (ldapIsAvailable());

    if ($ldap_virusquarantine eq "") {
      $$lm{menuitems}{$i} = {
        "prompt" => "Anti-virus quarantine user:",
        "var" => \$config{VIRUSQUARANTINE},
        "callback" => \&setAmavisVirusQuarantine
        };
      $i++;
    } else {
      $config{VIRUSQUARANTINE} = $ldap_virusquarantine;
    }

    $$lm{menuitems}{$i} = {
      "prompt" => "Enable automated spam training:",
      "var" => \$config{DOTRAINSA},
      "callback" => \&toggleYN,
      "arg" => "DOTRAINSA",
      };
    $i++;
    if ($config{DOTRAINSA} eq "yes") {

      my $ldap_trainsaspam = getLdapConfigValue("zimbraSpamIsSpamAccount")
        if (ldapIsAvailable());

      if ($ldap_trainsaspam eq "") {
        $$lm{menuitems}{$i} = {
          "prompt" => "Spam training user:",
          "var" => \$config{TRAINSASPAM},
          "callback" => \&setTrainSASpam
          };
        $i++;
      } else {
        $config{TRAINSASPAM} = $ldap_trainsaspam;
      }


      my $ldap_trainsaham = getLdapConfigValue("zimbraSpamIsNotSpamAccount")
        if (ldapIsAvailable());

      if ($ldap_trainsaham eq "") {
        $$lm{menuitems}{$i} = {
          "prompt" => "Non-spam(Ham) training user:",
          "var" => \$config{TRAINSAHAM},
          "callback" => \&setTrainSAHam
          };
        $i++;
      } else {
        $config{TRAINSAHAM} = $ldap_trainsaham;
      }
    }

    $$lm{menuitems}{$i} = {
      "prompt" => "SMTP host:",
      "var" => \$config{SMTPHOST},
      "callback" => \&setSmtpHost,
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Web server HTTP port:",
      "var" => \$config{HTTPPORT},
      "callback" => \&setHttpPort,
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Web server HTTPS port:",
      "var" => \$config{HTTPSPORT},
      "callback" => \&setHttpsPort,
      };
    $i++;
    if(!isEnabled("carbonio-proxy") && $config{"zimbraWebProxy"} eq "TRUE") {
       $$lm{menuitems}{$i} = {
         "prompt" => "HTTP proxy port:",
         "var" => \$config{HTTPPROXYPORT},
         "callback" => \&setHttpProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "HTTPS proxy port:",
         "var" => \$config{HTTPSPROXYPORT},
         "callback" => \&setHttpsProxyPort,
       };
       $i++;
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Web server mode:",
      "var" => \$config{MODE},
      "callback" => \&setStoreMode,
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "IMAP server port:",
      "var" => \$config{IMAPPORT},
      "callback" => \&setImapPort,
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "IMAP server SSL port:",
      "var" => \$config{IMAPSSLPORT},
      "callback" => \&setImapSSLPort,
      };
    $i++;
    if(!isEnabled("carbonio-proxy") && $config{"zimbraMailProxy"} eq "TRUE") {
       $$lm{menuitems}{$i} = {
         "prompt" => "IMAP proxy port:",
         "var" => \$config{IMAPPROXYPORT},
         "callback" => \&setImapProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "IMAP SSL proxy port:",
         "var" => \$config{IMAPSSLPROXYPORT},
         "callback" => \&setImapSSLProxyPort,
       };
       $i++;
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "POP server port:",
      "var" => \$config{POPPORT},
      "callback" => \&setPopPort,
      };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "POP server SSL port:",
      "var" => \$config{POPSSLPORT},
      "callback" => \&setPopSSLPort,
      };
    $i++;
    if(!isEnabled("carbonio-proxy") && $config{"zimbraMailProxy"} eq "TRUE") {
       $$lm{menuitems}{$i} = {
         "prompt" => "POP proxy port:",
         "var" => \$config{POPPROXYPORT},
         "callback" => \&setPopProxyPort,
       };
       $i++;
       $$lm{menuitems}{$i} = {
         "prompt" => "POP SSL proxy port:",
         "var" => \$config{POPSSLPROXYPORT},
         "callback" => \&setPopSSLProxyPort,
       };
       $i++;
    }
    if (!isInstalled("carbonio-proxy") && $newinstall) {
      $$lm{menuitems}{$i} = {
        "prompt" => "Configure for use with mail proxy:",
        "var" => \$config{zimbraMailProxy},
        "callback" => \&toggleTF,
        "arg" => "zimbraMailProxy",
      };
      $i++;
      $$lm{menuitems}{$i} = {
        "prompt" => "Configure for use with web proxy:",
        "var" => \$config{zimbraWebProxy},
        "callback" => \&toggleTF,
        "arg" => "zimbraWebProxy",
      };
      $i++;
    }
    $$lm{menuitems}{$i} = {
      "prompt" => "Install mailstore (service webapp):",
      "var" => \$config{SERVICEWEBAPP},
      "callback" => \&toggleSERVICEWEBAPP,
      "arg" => "SERVICEWEBAPP"
    };
    $i++;
    $$lm{menuitems}{$i} = {
      "prompt" => "Install UI (zimbra,zimbraAdmin webapps):",
      "var" => \$config{UIWEBAPPS},
      "callback" => \&toggleYN,
      "arg" => "UIWEBAPPS"
    };
    $i++;
  }
  return $lm;
}

sub displaySubMenuItems {
  my $items = shift;
  my $parentmenuvar = shift;
  my $indent = shift;

  if (defined($$items{createsub})) {
    $items = &{$$items{createsub}}($$items{createarg});
  }
#  print "$indent$$items{title}\n";
  foreach my $i (sort menuSort keys %{$$items{menuitems}}) {
    if (defined($$items{menuitems}{$i}{var}) &&
      $$items{menuitems}{$i}{var} == $parentmenuvar) {next;}
    my $len = 44-(length($indent));
    my $v;
    my $ind = $indent;
    if (defined $$items{menuitems}{$i}{var}) {
      $v = ${$$items{menuitems}{$i}{var}};
      if ($v eq "" || $v eq "none" || $v eq "UNSET") { $v = "UNSET"; $ind=~s/ /*/g; }
      if ($v eq "Not Verified") { $v = "Not Verified"; $ind=~s/ /*/g; }
    }
    printf ("%s +%-${len}s %-30s\n", $ind,
      $$items{menuitems}{$i}{prompt}, $v);
    if (defined ($$items{menuitems}{$i}{submenu}) ) {
      displaySubMenuItems($$items{menuitems}{$i}{submenu},"$indent  ");
    }
  }
}

sub menuSort {
  if ( ($a eq int($a)) && ($b eq int($b)) ) {
    return $a <=> $b;
  }
  return $a cmp $b;
}

sub displayMenu {
  my $items = shift;
  while (1) {
    if (defined($$items{createsub})) {
      $items = &{$$items{createsub}}($$items{createarg});
    }

    print "\n$$items{title}\n\n";
    foreach my $i (sort menuSort keys %{$$items{menuitems}}) {
      my $v;
      my $ind = "  ";
      if (defined $$items{menuitems}{$i}{var}) {
        $v = ${$$items{menuitems}{$i}{var}};
        if ($v eq "" || $v eq "none" || $v eq "UNSET") { $v = "UNSET"; $ind="**"; }
        if ($v eq "Not Verified") { $ind="**"; }
      }
      my $subMenuCheck = 1;
      if (defined ($$items{menuitems}{$i}{submenu}) ||
        defined ($$items{menuitems}{$i}{callback}) ) {
        if (defined ($$items{menuitems}{$i}{submenu})) {
          $subMenuCheck = checkMenuConfig($$items{menuitems}{$i}{submenu});
        }
        printf ("${ind}%2s) %-40s %-30s\n", $i,
          $$items{menuitems}{$i}{prompt}, $v);
      } else {
        # Disabled items
        printf ("${ind}    %-40s %-30s\n",
          $$items{menuitems}{$i}{prompt}, $v);
      }
      if ($config{EXPANDMENU} eq "yes" || !$subMenuCheck) {
        if (defined ($$items{menuitems}{$i}{submenu}) ) {
          displaySubMenuItems($$items{menuitems}{$i}{submenu},
            $$items{menuitems}{$i}{var},"       ");
          print "\n";
        }
      }
    }
    if (defined($$items{lastitem})) {
      printf ("  %2s) %-40s\n", $$items{lastitem}{selector},
        $$items{lastitem}{prompt});
    }
    my $menuprompt = "\n";
    if (defined($$items{promptitem})) {
      $menuprompt .= $$items{promptitem}{prompt};
    } else {
      $menuprompt .= "Select ";
    }
    if (defined($$items{help})) {
      $menuprompt .= " (? - help) ";
    }
    print "$menuprompt";
    if (defined $$items{default}) {
      print "[$$items{default}] ";
    }
    my $r = <>;
    chomp $r;
    if ($r eq "") { $r = $$items{default}; }
    if ($r eq "") { next; }
    if ($r eq $$items{lastitem}{selector}) {
      if ($$items{lastitem}{action} eq "quit") {
        if (verifyQuit()) {
          exit 0;
        }
      } elsif ($$items{lastitem}{action} eq "return") {
        return;
      }
    } elsif (defined $$items{help} && $r eq "?") {
      print "\n\n";
      print $$items{help}{helptext};
      print "\n";
      ask("Press any key to continue", "");
      print "\n\n";
    } elsif (defined $$items{promptitem} && $r eq $$items{promptitem}{selector}) {
      if (defined $$items{promptitem}{callback}) {
        &{$$items{promptitem}{callback}}($$items{promptitem}{arg});
      } elsif (defined $$items{promptitem}{action}) {
        if ($$items{promptitem}{action} eq "quit") {
          if (verifyQuit()) {
            exit 0;
          }
        } elsif ($$items{promptitem}{action} eq "return") {
          return;
        }
      }
    } elsif (defined $$items{menuitems}{$r}) {
      print "\n";
      if (defined $$items{menuitems}{$r}{callback}) {
        &{$$items{menuitems}{$r}{callback}}($$items{menuitems}{$r}{arg});
      } elsif (defined ($$items{menuitems}{$r}{submenu})) {
        displayMenu($$items{menuitems}{$r}{submenu});
      }
    } else {
      ask("Invalid selection! - press any key to continue", "");
      print "\n\n";
    }
  }
}

sub createMainMenu {
  my %mm = ();
  $mm{createsub} = \&createMainMenu;
  $mm{title} = "Main menu";
  $mm{help} = {
    "selector" => "?",
    "prompt" => "Help",
    "action" => "help",
    "helptext" =>
      "Main Menu help\n\n".
      "Items marked with ** MUST BE CONFIGURED prior to applying configuration\n\n".
      "",
    };
  $mm{lastitem} = {
    "selector" => "q",
    "prompt" => "Quit",
    "action" => "quit",
    };
  my $i = 1;
  my $submenu = createCommonMenu("carbonio-core");
  $mm{menuitems}{$i} = {
    "prompt" => "Common Configuration:",
    "submenu" => $submenu,
  };
  $i++;
  foreach my $package (@packageList) {
    if ($package eq "carbonio-core") {next;}
    if ($package eq "carbonio-memcached") {next;}
    if (defined($installedPackages{$package})) {
      if ($package =~ /logger/) {
        $mm{menuitems}{$i} = {
          "prompt" => "$package:",
          "var" => \$enabledPackages{$package},
          "callback" => \&toggleEnabled,
          "arg" => $package
        };
        $i++;
        next;
      }
      my $submenu = createPackageMenu($package);
      $mm{menuitems}{$i} = {
        "prompt" => "$package:",
        "var" => \$enabledPackages{$package},
        "submenu" => $submenu,
      };
      $i++;
    } else {
      #push @mm, "$package not installed";
    }
  }
  $i = &preinstall::mainMenuExtensions(\%mm, $i);
#  $mm{menuitems}{r} = {
#    "prompt" => "Start servers after configuration",
#    "callback" => \&toggleYN,
#    "var" => \$config{STARTSERVERS},
#    "arg" => "STARTSERVERS"
#    };
  if ($config{EXPANDMENU} eq "yes") {
    $mm{menuitems}{c} = {
      "prompt" => "Collapse menu",
      "callback" => \&toggleYN,
      "arg" => "EXPANDMENU"
      };
  } else {
    $mm{menuitems}{x} = {
      "prompt" => "Expand menu",
      "callback" => \&toggleYN,
      "arg" => "EXPANDMENU"
      };
  }
  # Allow save of even incomplete config
  $mm{menuitems}{s} = {
    "prompt" => "Save config to file",
    "callback" => \&saveConfig,
    };
  if (checkMenuConfig(\%mm)) {
    $mm{promptitem} = {
      "selector" => "y",
      "prompt" => "*** CONFIGURATION COMPLETE - press 'y' to apply configuration\nSelect from menu, or press 'y' to apply config",
      "callback" => \&applyConfig,
      };
  } else {
    $mm{promptitem} = {
      "selector" => "qqazyre",
      "prompt" => "Address unconfigured (**) items ",
      "callback" => \&applyConfig,
      };
    if (!ldapIsAvailable() && $ldapConfigured) {
      $mm{promptitem}{prompt} .= "or correct ldap configuration ";
    }
    if ($config{LDAPHOST} ne $config{HOSTNAME} && !ldapIsAvailable() && isInstalled("carbonio-directory-server")) {
      $mm{promptitem}{prompt} .= "and enable ldap replication on ldap master "
        if (checkLdapReplicationEnabled($config{zimbra_ldap_userdn},$config{LDAPADMINPASS}));
    }
  }
  return \%mm;
}

sub checkMenuConfig {
  my $items = shift;

  my $needldapverified = 0;

  foreach my $i (sort menuSort keys %{$$items{menuitems}}) {
    my $v;
    my $ind = "  ";
    if (defined $$items{menuitems}{$i}{var}) {
      $v = ${$$items{menuitems}{$i}{var}};
      if ($v eq "" || $v eq "none" || $v eq "UNSET" || $v eq "Not Verified") { return 0; }
      foreach my $var (qw(LDAPHOST LDAPPORT)) {
        if ($$items{menuitems}{$i}{var} == \$config{$var}) {
          $needldapverified = 1;
        }
      }
    }
    if (defined ($$items{menuitems}{$i}{submenu}) ) {
      if (!checkMenuConfig($$items{menuitems}{$i}{submenu})) {
        return 0;
      }
    }
  }
  if ($needldapverified) {
    return 1 if ($config{LDAPHOST} eq $config{HOSTNAME} && !$ldapConfigured);
    return 0 if (!ldapIsAvailable());
  }
  if (defined($installedPackages{"carbonio-appserver"}) && $config{SERVICEWEBAPP} eq "no" && $config{UIWEBAPPS} eq "no" ) {
    $config{SERVICEWEBAPP}="UNSET";
    $config{UIWEBAPPS}="UNSET";
    return 0;
  }
  return 1;
}

sub ldapIsAvailable {
  my $failedcheck=0;
  if (($config{LDAPHOST} eq $config{HOSTNAME}) && !$ldapConfigured) {
    detail("This is the ldap master and ldap hasn't been configured yet.");
    return 0;
  }

  # check zimbra ldap admin user binding to the master
  if ($config{LDAPADMINPASS} eq "" || $config{LDAPPORT} eq "" || $config{LDAPHOST} eq "") {
    detail ( "ldap configuration not complete\n" );
    return 0;
  }

  if (checkLdapBind($config{zimbra_ldap_userdn},$config{LDAPADMINPASS})) {
    detail ("Couldn't bind to $config{LDAPHOST} as $config{zimbra_ldap_userdn}\n");
    $config{LDAPADMINPASSSET} = "Not Verified";
    $failedcheck++;
  } else {
    detail ("Verified $config{zimbra_ldap_userdn} on $config{LDAPHOST}.\n");
    $config{LDAPADMINPASSSET} = "set";
    setLocalConfig ("zimbra_ldap_password", $config{LDAPADMINPASS});
    setLdapDefaults() if ($config{LDAPHOST} ne $config{HOSTNAME});
  }

  # check nginx user binding to the master
  if (isInstalled("carbonio-proxy")) {
    if ($config{ldap_nginx_password} eq "") {
      detail ("nginx configuration not complete\n");
      $failedcheck++;
    }
    my $binduser = "uid=zmnginx,cn=appaccts,$config{ldap_dit_base_dn_config}";
    if (checkLdapBind($binduser,$config{ldap_nginx_password})) {
      detail ("Couldn't bind to $config{LDAPHOST} as $binduser\n");
      $config{LDAPNGINXPASSSET} = "Not Verified";
      $failedcheck++;
    } else {
      detail ("Verified $binduser on $config{LDAPHOST}.\n");
      $config{LDAPNGINXPASSSET} = "set";
    }
  }
  # check postfix and amavis user binding to the master
  if (isInstalled("carbonio-mta")) {
    if ($config{LDAPPOSTPASS} eq "" || $config{LDAPAMAVISPASS} eq "") {
      detail ("mta configuration not complete\n");
      $failedcheck++;
    }
    my $binduser = "uid=zmpostfix,cn=appaccts,$config{ldap_dit_base_dn_config}";
    if (checkLdapBind($binduser,$config{LDAPPOSTPASS})) {
      detail ("Couldn't bind to $config{LDAPHOST} as $binduser\n");
      $config{LDAPPOSTPASSSET} = "Not Verified";
      detail ("Setting LDAPPOSTPASSSET to $config{LDAPPOSTPASSSET}") if $debug;
      $failedcheck++;
    } else {
      detail ("Verified $binduser on $config{LDAPHOST}.\n");
      $config{LDAPPOSTPASSSET} = "set";
    }
    my $binduser = "uid=zmamavis,cn=appaccts,$config{ldap_dit_base_dn_config}";
    if (checkLdapBind($binduser,$config{LDAPAMAVISPASS})) {
      detail ("Couldn't bind to $config{LDAPHOST} as $binduser\n");
      $config{LDAPAMAVISPASSSET} = "Not Verified";
      detail ("Setting LDAPAMAVISPASSSET to $config{LDAPAMAVISPASSSET}") if $debug;
      $failedcheck++;
    } else {
      detail ("Verified $binduser on $config{LDAPHOST}.\n");
      $config{LDAPAMAVISPASSSET}="set";
    }
  }

  # check replication user binding to master
  if (isInstalled("carbonio-directory-server") && $config{LDAPHOST} ne $config{HOSTNAME}) {
    if ($config{LDAPREPPASS} eq "") {
      detail ("ldap configuration not complete. Ldap Replication password is not set.\n");
      $failedcheck++;
    }
    my $binduser = "uid=zmreplica,cn=admins,$config{ldap_dit_base_dn_config}";
    if (checkLdapBind($binduser,$config{LDAPREPPASS})) {
      detail ("Couldn't bind to $config{LDAPHOST} as $binduser\n");
      $config{LDAPREPPASSSET}="Not Verified";
      detail ("Setting LDAPREPPASSSET to $config{LDAPREPPASSSET}") if $debug;
      $failedcheck++;
    } else {
      detail ("Verified $binduser on $config{LDAPHOST}.\n");
      $config{LDAPREPPASSSET}="set";
    }
    if (checkLdapReplicationEnabled($config{zimbra_ldap_userdn},$config{LDAPADMINPASS})) {
      detail ("ldap configuration not complete. Unable to verify ldap replication is enabled on $config{LDAPHOST}\n");
      $failedcheck++;
    } else {
      detail ("ldap replication ability verified\n");
    }
  }
  return ($failedcheck > 0) ? 0 : 1;
}

sub checkLdapBind() {
  my ($binduser,$bindpass) = @_;

  detail( "Checking ldap on $config{LDAPHOST}:$config{LDAPPORT}");
  my $ldap;
  my $ldap_secure = (($config{LDAPPORT} == "636") ? "s" : "");
  my $ldap_url = "ldap${ldap_secure}://$config{LDAPHOST}:$config{LDAPPORT}";
  unless($ldap = Net::LDAP->new($ldap_url)) {
    detail("failed: Unable to contact ldap at $ldap_url: $!");
    return 1;
  }

  if ($ldap_secure ne "s" && $config{zimbra_require_interprocess_security}) {
    $starttls = 1;
    my $result = $ldap->start_tls(verify=>'none');
    if ($result->code()) {
      detail("Unable to startTLS: $!\n");
      detail("Disabling the requirement for interprocess security.\n");
      $config{zimbra_require_interprocess_security} = 0;
      $config{ZIMBRA_REQ_SECURITY}="no";
      $starttls = 0;
    }
  } else {
    $starttls = 0;
  }
  my $result = $ldap->bind($binduser, password => $bindpass);
  if ($result->code()) {
    detail ("Unable to bind to $ldap_url with user $binduser: $!");
    return 1;
  } else {
    $ldap->unbind;
    detail ("Verified ldap running at $ldap_url\n");
    if ($newinstall) {
      setLocalConfig("ldap_url", $ldap_url);
      setLocalConfig("ldap_starttls_supported", $starttls);
      setLocalConfig("zimbra_require_interprocess_security", $config{zimbra_require_interprocess_security});
    }
    setLocalConfig("ssl_allow_untrusted_certs", "true") if ($newinstall);
    return 0;
  }

}

sub checkLdapReplicationEnabled() {
  my ($binduser,$bindpass) = @_;
  detail( "Checking ldap replication is enabled on $config{LDAPHOST}:$config{LDAPPORT}");
  my $ldap;
  my $ldap_secure = (($config{LDAPPORT} == "636") ? "s" : "");
  my $ldap_url = "ldap${ldap_secure}://$config{LDAPHOST}:$config{LDAPPORT}";
  unless($ldap = Net::LDAP->new($ldap_url)) {
    detail("failed: Unable to contact ldap at $ldap_url: $!");
    return 1;
  }
  if ($ldap_secure ne "s" && $starttls) {
    my $result = $ldap->start_tls(verify=>'none');
    if ($result->code()) {
      detail("Unable to startTLS: $!\n");
      detail("Disabling the requirement for interprocess security.\n");
      $config{zimbra_require_interprocess_security} = 0;
      $config{ZIMBRA_REQ_SECURITY}="no";
      $starttls = 0;
    }
  }
  my $result = $ldap->bind($binduser, password => $bindpass);
  if ($result->code()) {
    detail ("Unable to bind to $ldap_url with user $binduser: $!");
    return 1;
  } else {
    my $result = $ldap->search(base=>"cn=accesslog", scope=>"base", filter=>"cn=accesslog", attrs=>['cn']);
    if ($result->code()) {
      detail("Unable to find accesslog database on master.\n");
      if ($config{LDAPREPLICATIONTYPE} eq "replica") {
        detail("Please run zmldapenablereplica on the master.\n");
      } elsif ($config{LDAPREPLICATIONTYPE} eq "mmr") {
        detail("Please run zmldapenable-mmr on the master.\n");
      }
      return 1;
    } else {
      detail("Verified ability to query accesslog on master.\n");
    }
  }
  return 0;
}

sub runAsRoot {
  my $cmd = shift;
  if ($cmd =~ /ldappass/ || $cmd =~ /init/ || $cmd =~ /zmprov -r -m -l ca/) {
    # Suppress passwords in log file
    my $c = (split ' ', $cmd)[0];
    detail ( "*** Running as root user: $c\n" );
  } else {
    detail ( "*** Running as root user: $cmd\n" );
  }
  my $rc;
  $rc = 0xffff & system("$cmd >> $logfile 2>&1");
  return $rc;
}

sub runAsZextras {
  my $cmd = shift;
  if ($cmd =~ /ldappass/ || $cmd =~ /init/ || $cmd =~ /zmprov -r -m -l ca/) {
    # Suppress passwords in log file
    my $c = (split ' ', $cmd)[0];
    detail ( "*** Running as zextras user: $c\n" );
  } else {
    detail ( "*** Running as zextras user: $cmd\n" );
  }
  my $rc;
  $rc = 0xffff & system("$SU \"$cmd\" >> $logfile 2>&1");
  return $rc;
}

sub runAsZextrasWithOutput {
  my $cmd = shift;
  if ($cmd =~ /ldappass/ || $cmd =~ /init/ || $cmd =~ /zmprov -r -m -l ca/) {
    # Suppress passwords in log file
    my $c = (split ' ', $cmd)[0];
    detail ( "*** Running as zextras user: $c\n" );
  } else {
    detail ( "*** Running as zextras user: $cmd\n" );
  }
  system("$SU \"$cmd\"");
  my $exit_value = $? >> 8;
  my $signal_num = $? & 127;
  my $dumped_core = $? & 128;
  detail ("DEBUG: exit status from cmd was $exit_value") if $debug;
  return $exit_value;
}

sub getLocalConfig {
  my ($key,$force) = @_;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key} && !$force);

  detail ( "Getting local config $key" );
  my $val = qx(/opt/zextras/bin/zmlocalconfig -x -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  detail ("DEBUG: LC Loaded $key=$val") if $debug;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

sub getLocalConfigRaw {
  my ($key,$force) = @_;

  return $main::loaded{lc}{$key}
    if (exists $main::loaded{lc}{$key} && !$force);

  detail ( "Getting local config $key" );
  my $val = qx(/opt/zextras/bin/zmlocalconfig -s -m nokey ${key} 2> /dev/null);
  chomp $val;
  detail ("DEBUG: LC Loaded $key=$val") if $debug;
  $main::loaded{lc}{$key} = $val;
  return $val;
}

sub deleteLocalConfig {
  my $key = shift;

  detail ( "Deleting local config $key" );
  my $rc = runAsZextras("/opt/zextras/bin/zmlocalconfig -u ${key} 2> /dev/null");
  if ($rc == 0) {
    detail ("DEBUG: deleted localconfig key $key") if $debug;
    delete($main::loaded{lc}{$key}) if (exists $main::loaded{lc}{$key});
    return 1;
  } else {
    detail ("DEBUG: failed to deleted localconfig key $key") if $debug;
    return undef
  }
}

sub setLocalConfig {
  my $key = shift;
  my $val = shift;

  if (exists $main::saved{lc}{$key} && $main::saved{lc}{$key} eq $val) {
    detail("Skipping update of unchanged value for $key=$val.");
    return;
  }
  detail ( "Setting local config $key to $val" );
  $main::saved{lc}{$key} = $val;
  $main::loaded{lc}{$key} = $val;
  $val =~ s/\$/\\\$/g;
  runAsZextras("/opt/zextras/bin/zmlocalconfig -f -e ${key}=\'${val}\' 2> /dev/null");
}

sub updateKeyValue {
  my ($sec,$key,$val,$sub) = @_;
  if ($key =~ /^\+(.*)/) {
    # TODO remove duplicates
    $main::loaded{$sec}{$sub}{$1}="$main::loaded{$sec}{$sub}{$1}\n$val";
    $main::saved{$sec}{$sub}{$1}=$main::loaded{$sec}{$sub}{$1};
  } elsif ($key =~ /^-(.*)/) {
    if (exists $main::loaded{$sec}{$sub}{$1}) {
      my %tmp = map { $_ => 1 } split(/\n/, $main::loaded{$sec}{$sub}{$1});
      delete $tmp{$val};
      $main::loaded{$sec}{$sub}{$1}=join "\n", keys %tmp;
      $main::saved{$sec}{$sub}{$1}=$main::loaded{$sec}{$sub}{$1};
    }
  } else {
    $main::loaded{$sec}{$sub}{$key}=$val;
    $main::saved{$sec}{$sub}{$key}=$val;
  }
}

sub ifKeyValueEquate {
  my ($sec,$key,$val,$sub) = @_;
  $key=$1 if ($key =~ /^[+|-](.*)/);
  detail("Checking to see if $key=$val has changed for $sec $sub\n") if $debug;
  if (exists $main::saved{$sec}{$sub}{$key} && $main::saved{$sec}{$sub}{$key} eq $val) {
    #detail("DEBUG: \"$main::saved{$sec}{$sub}{$key}\" eq \"$val\"\n") if $debug;
    return 1;
  } else {
    #detail("DEBUG: \"$main::saved{$sec}{$sub}{$key}\" ne \"$val\"\n") if $debug;
    return 0;
  }
}

#
#  setLdapGlobalConfig(key, val [, key, val ...])
#
sub setLdapGlobalConfig {
  my $zmprov_arg_str;
  my $sec="gcf";
  while (@_){
    my $key = shift;
    my $val = shift;
    detail("entering function: $sec $key=$val\n");
    if (ifKeyValueEquate($sec,$key,$val,$sec)) {
      detail("Skipping update of unchanged value for $key=$val.");
    } else {
      detail("Updating cached global config attribute $key=$val");
      updateKeyValue($sec,$key,$val,$sec);
      $zmprov_arg_str .= " $key \'$val\'";
    }
  }
  if ($zmprov_arg_str) {
    my $rc = runAsZextras("$ZMPROV mcf $zmprov_arg_str");
    return $rc;
  }
}

#
# setLdapServerConfig([server,] key, val [, key, val ...])
#
sub setLdapServerConfig {
  my $zmprov_arg_str;
  my $sec="gs";
  my $server;

  if (($#_ % 2) == 0) {
    $server = shift;
  } else {
    $server = $config{HOSTNAME};
  }
  return undef if ($server eq "");
  while (@_) {
    my $key = shift;
    my $val = shift;

    if (ifKeyValueEquate($sec,$key,$val,$server)) {
      detail("Skipping update of unchanged value for $key=$val.");
    } else {
      detail("Updating cached config attribute for Server $server: $key=$val");
      updateKeyValue($sec,$key,$val,$server);
      $zmprov_arg_str .= " $key \'$val\'";
    }
  }

  if ($zmprov_arg_str) {
    my $rc = runAsZextras("$ZMPROV ms $server $zmprov_arg_str");
    return $rc;
  }
}


#
# setLdapDomainConfig([domain,] key, val [, key, val ...])
#
sub setLdapDomainConfig {
  my $zmprov_arg_str;
  my $domain;

  if (($#_ % 2) == 0) {
    $domain = shift;
  } else {
    $domain = getLdapConfigValue("zimbraDefaultDomainName");
  }
  return undef if ($domain eq "");

  my $sec="domain";
  while (@_) {
    my $key = shift;
    my $val = shift;
    if (ifKeyValueEquate($sec,$key,$val,$domain)) {
      detail("Skipping update of unchanged value for $key=$val.");
    } else {
      detail("Updating cached config attribute for Domain $domain: $key=$val");
      updateKeyValue($sec,$key,$val,$domain);
      $zmprov_arg_str .= " $key \'$val\'";
    }
  }

  if ($zmprov_arg_str) {
    my $rc = runAsZextras("$ZMPROV md $domain $zmprov_arg_str");
    return $rc;
  }
}

#
# setLdapCOSConfig([cos,] key, val [, key, val ...])
#
sub setLdapCOSConfig {
  my $zmprov_arg_str;
  my $cos;

  if (($#_ % 2) == 0) {
    $cos = shift;
  } else {
    $cos = 'default';
  }

  my $sec="gc";
  while (@_) {
    my $key = shift;
    my $val = shift;
    if (ifKeyValueEquate($sec,$key,$val,$cos)) {
      detail("Skipping update of unchanged value for $key=$val.");
	} else {
      detail("Updating cached config attribute for COS $cos: $key=$val");
      updateKeyValue($sec,$key,$val,$cos);
      $zmprov_arg_str .= " $key \'$val\'";
    }
  }

  if ($zmprov_arg_str) {
    my $rc = runAsZextras("$ZMPROV mc $cos $zmprov_arg_str");
    return $rc;
  }
}

#
# setLdapAccountConfig(acct, key, val [, key, val ...])
#
sub setLdapAccountConfig {
  my $zmprov_arg_str;
  my $acct;
  if (($#_ % 2) == 0) {
    $acct = shift;
  }
  return undef if ($acct eq "");

  my $sec="acct";
  while (@_) {
    my $key = shift;
    my $val = shift;
    if (ifKeyValueEquate($sec,$key,$val,$acct)) {
      detail("Skipping update of unchanged value for $key=$val.");
    } else {
      detail("Updating cached config attribute for Account $acct: $key=$val");
      updateKeyValue($sec,$key,$val,$acct);
      $zmprov_arg_str .= " $key \'$val\'";
    }
  }

  if ($zmprov_arg_str) {
    my $rc = runAsZextras("$ZMPROV ma $acct $zmprov_arg_str");
    return $rc;
  }
}

sub configLCValues {

  if ($configStatus{configLCValues} eq "CONFIGURED") {
    configLog("configLCValues");
    return 0;
  }

  progress ("Setting local config values...");
  setLocalConfig ("zimbra_server_hostname", lc($config{HOSTNAME}));
  setLocalConfig ("zimbra_require_interprocess_security", $config{zimbra_require_interprocess_security});

  if($newinstall) {
    if ($config{LDAPPORT} == 636) {
      setLocalConfig ("ldap_master_url", "ldaps://$config{LDAPHOST}:$config{LDAPPORT}");
      setLocalConfig ("ldap_url", "ldaps://$config{LDAPHOST}:$config{LDAPPORT}");
      setLocalConfig ("ldap_starttls_supported", 0);
    } else {
      setLocalConfig ("ldap_master_url", "ldap://$config{LDAPHOST}:$config{LDAPPORT}");
      if ($config{ldap_url} eq "") {
        setLocalConfig ("ldap_url", "ldap://$config{LDAPHOST}:$config{LDAPPORT}");
        if ($config{zimbra_require_interprocess_security}) {
          setLocalConfig ("ldap_starttls_supported", 1);
        } else {
          setLocalConfig ("ldap_starttls_supported", 0);
        }
      } else {
        setLocalConfig ("ldap_url", "$config{ldap_url}");
        if ($config{ldap_url} !~ /^ldaps/i && $config{zimbra_require_interprocess_security}) {
          setLocalConfig ("ldap_starttls_supported", 1);
        } else {
          setLocalConfig ("ldap_starttls_supported", 0);
        }
      }
    }
  }

  # set default zmprov bahaviour
  if (isEnabled("carbonio-appserver") && isStoreServiceNode()) {
    setLocalConfig ("zimbra_zmprov_default_to_ldap", "false");
  } else {
    setLocalConfig ("zimbra_zmprov_default_to_ldap", "true");
  }

  setLocalConfig ("ldap_port", "$config{LDAPPORT}");
  setLocalConfig ("ldap_host", "$config{LDAPHOST}");

  my $uid = qx(id -u zextras);
  chomp $uid;
  my $gid = qx(id -g zextras);
  chomp $gid;
  setLocalConfig ("zimbra_uid", $uid);
  setLocalConfig ("zimbra_gid", $gid);
  setLocalConfig ("zimbra_user", "zextras");

  if (defined $config{AVUSER}) {
    setLocalConfig ("av_notify_user", $config{AVUSER})
  }
  if (defined $config{AVDOMAIN}) {
    setLocalConfig ("av_notify_domain", $config{AVDOMAIN})
  }

  setLocalConfig ("ssl_allow_untrusted_certs", "true") if ($newinstall);
  setLocalConfig ("ssl_allow_mismatched_certs", "true") if ($newinstall);
  setLocalConfig ("ssl_default_digest", $config{ssl_default_digest});
  setLocalConfig ("mailboxd_java_heap_size", $config{MAILBOXDMEMORY});
  setLocalConfig ("mailboxd_directory", $config{mailboxd_directory});
  setLocalConfig ("mailboxd_keystore", $config{mailboxd_keystore});
  setLocalConfig ("mailboxd_server", $config{mailboxd_server});
  setLocalConfig ("mailboxd_truststore", "$config{mailboxd_truststore}");
  setLocalConfig ("mailboxd_truststore_password", "$config{mailboxd_truststore_password}");
  setLocalConfig ("mailboxd_keystore_password", "$config{mailboxd_keystore_password}");
  setLocalConfig ("zimbra_ldap_userdn", "$config{zimbra_ldap_userdn}");
  setLocalConfig ("ldap_dit_base_dn_config", "$config{ldap_dit_base_dn_config}")
    if ($config{ldap_dit_base_dn_config} ne "cn=zimbra");

  configLog ("configLCValues");

  progress ("done.\n");

}

sub configCASetup {

  if ($configStatus{configCASetup} eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/ca" ) {
    configLog("configCASetup");
    return 0;
  }

  if ($config{LDAPHOST} ne $config{HOSTNAME}) {
    # fetch it from ldap if ldap has been configed
    progress("Updating ldap_root_password and zimbra_ldap_password...");
    setLocalConfig ("ldap_root_password", $config{LDAPROOTPASS});
    setLocalConfig ("zimbra_ldap_password", $config{LDAPADMINPASS});
    progress ( "done.\n" );
  }
  progress ( "Setting up CA..." );
  if (! $newinstall) {
    if (-f "/opt/zextras/conf/ca/ca.pem") {
      my $rc = runAsRoot("/opt/zextras/common/bin/openssl verify -purpose sslserver -CAfile /opt/zextras/conf/ca/ca.pem /opt/zextras/conf/ca/ca.pem | egrep \"^error 10\"");
      $needNewCert = "-new" if ($rc == 0);
    }
  }

  # regenerate the certificate authority if this is the ldap master and
  # either the ca is expired from the test above or the ca directory doesn't exist.
  my $needNewCA;
  if (isLdapMaster()) {
    $needNewCA = "-new" if (! -d "/opt/zextras/ssl/carbonio/ca" || $needNewCert eq "-new");
  }

  # we are going to download a new CA or otherwise create one so we need to regenerate the self signed cert.
  $needNewCert = "-new" if (! -d "/opt/zextras/ssl/carbonio/ca");

  my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createca $needNewCA");
  if ($rc != 0) {
    progress ( "failed.\n" );
    exit 1;
  } else {
    progress ( "done.\n" );
  }

  progress ( "Deploying CA to /opt/zextras/conf/ca ..." );
  my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deployca -localonly");
  if ($rc != 0) {
    progress ( "failed.\n" );
    exit 1;
  } else {
    progress ( "done.\n" );
  }


  configLog("configCASetup");
}

sub configSetupLdap {

  if ($configStatus{configSetupLdap} eq "CONFIGURED") {
    detail("ldap already configured bypassing configuration\n");
    configLog("configSetupLdap");
    return 0;
  }

  if (!$ldapConfigured && isEnabled("carbonio-directory-server") && ! -f "/opt/zextras/.enable_replica" && $newinstall && ($config{LDAPHOST} eq $config{HOSTNAME})) {
    progress ( "Initializing ldap..." ) ;
    if (my $rc = runAsZextras("/opt/zextras/libexec/zmldapinit \'$config{LDAPROOTPASS}\' \'$config{LDAPADMINPASS}\'")) {
      progress ( "failed. ($rc)\n" );
      failConfig();
    } else {
      progress ( "done.\n" );
      if ($ldapRepChanged == 1) {
         progress ( "Setting replication password..." );
         runAsZextras ("/opt/zextras/bin/zmldappasswd -l \'$config{LDAPREPPASS}\'");
         progress ( "done.\n" );
      }
      if ($ldapPostChanged == 1) {
         progress ( "Setting Postfix password..." );
         runAsZextras ("/opt/zextras/bin/zmldappasswd -p \'$config{LDAPPOSTPASS}\'");
         progress ( "done.\n" );
      }
      if ($ldapAmavisChanged == 1) {
         progress ( "Setting amavis password..." );
         runAsZextras ("/opt/zextras/bin/zmldappasswd -a \'$config{LDAPAMAVISPASS}\'");
         progress ( "done.\n" );
      }
      if ($ldapNginxChanged == 1) {
         progress ( "Setting nginx password..." );
         runAsZextras ("/opt/zextras/bin/zmldappasswd -n \'$config{ldap_nginx_password}\'");
         progress ( "done.\n" );
      }
    }
    if ($config{FORCEREPLICATION} eq "yes") {
      my $rc = runAsZextras ("/opt/zextras/libexec/zmldapenablereplica");
      my $file="/opt/zextras/.enable_replica";
      open(ER,">>$file");
      close ER;
    }
  } elsif (isEnabled("carbonio-directory-server")) {
    my $rc;
    if ($newinstall) {
      $rc = runAsZextras ("/opt/zextras/libexec/zmldapapplyldif");
    }
    if (!$newinstall) {
      $rc = runAsZextras ("/opt/zextras/libexec/zmldapupdateldif");
    }
    # enable replica for both new and upgrade installs if we are adding ldap
    if ($config{LDAPHOST} ne $config{HOSTNAME} || -f "/opt/zextras/.enable_replica") {
      progress("Updating ldap_root_password and zimbra_ldap_password...");
      setLocalConfig ("ldap_root_password", $config{LDAPROOTPASS});
      setLocalConfig ("zimbra_ldap_password", $config{LDAPADMINPASS});
      setLocalConfig ("ldap_replication_password", "$config{LDAPREPPASS}");
      if($newinstall && $config{LDAPREPLICATIONTYPE} eq "mmr") {
        if ($ldapPostChanged == 1) {
           progress ( "Setting Postfix password..." );
           runAsZextras ("/opt/zextras/bin/zmldappasswd -p \'$config{LDAPPOSTPASS}\'");
           progress ( "done.\n" );
        }
        if ($ldapAmavisChanged == 1) {
           progress ( "Setting amavis password..." );
           runAsZextras ("/opt/zextras/bin/zmldappasswd -a \'$config{LDAPAMAVISPASS}\'");
           progress ( "done.\n" );
        }
        if ($ldapNginxChanged == 1) {
           progress ( "Setting nginx password..." );
           runAsZextras ("/opt/zextras/bin/zmldappasswd -n \'$config{ldap_nginx_password}\'");
           progress ( "done.\n" );
        }
      }
      progress("done.\n");
      progress ( "Enabling ldap replication..." );
      if ( ! -f "/opt/zextras/.enable_replica" ) {
         if ($newinstall && $config{LDAPREPLICATIONTYPE} eq "mmr") {
           setLocalConfig ("ldap_is_master", "true");
           my $ldapMasterUrl = getLocalConfig ("ldap_master_url");
           my $proto = "ldap";
           if ($config{LDAPPORT} == "636") {
             $proto="ldaps";
           }
           setLocalConfig("ldap_url", "$proto://$config{HOSTNAME}:$config{LDAPPORT} $ldapMasterUrl");
           if ($ldapMasterUrl !~ /\/$/) {
             $ldapMasterUrl=$ldapMasterUrl."/";
           }
           runAsZextras ("/opt/zextras/bin/ldap start");
           $rc = runAsZextras ("/opt/zextras/libexec/zmldapenable-mmr -s $config{LDAPSERVERID} -m $ldapMasterUrl");
         } else {
           $rc = runAsZextras ("/opt/zextras/libexec/zmldapenablereplica");
         }
         my $file="/opt/zextras/.enable_replica";
         open(ER,">>$file");
         close ER;
      }
      if ($rc == 0) {
        if (!isEnabled("carbonio-appserver")) {
          $config{DOCREATEADMIN} = "no";
        }
        $config{DOCREATEDOMAIN} = "no";
        progress ( "done.\n" );
        progress("Stopping ldap...");
        runAsZextras ("/opt/zextras/bin/ldap stop");
        progress("done.\n");
        startLdap();
      } else {
        progress ("failed.\n");
        progress ("You will have to correct the problem and manually enable replication.\n");
        progress ("Disabling ldap on $config{HOSTNAME}...");
        my $rc = setLdapServerConfig("-zimbraServiceEnabled", "ldap");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
        progress("Stopping ldap...");
        runAsZextras ("/opt/zextras/bin/ldap stop");
        progress("done.\n");
      }
    }


    # zmldappasswd starts ldap and re-applies the ldif
    if ($ldapRootPassChanged || $ldapAdminPassChanged || $ldapRepChanged || $ldapPostChanged || $ldapAmavisChanged || $ldapNginxChanged) {
      if ($ldapRootPassChanged) {
         progress ( "Setting ldap root password..." );
         runAsZextras ("/opt/zextras/bin/zmldappasswd -r $config{LDAPROOTPASS}");
         progress ( "done.\n" );
      }
      if ($ldapAdminPassChanged) {
         progress ( "Setting ldap admin password..." );
         if ($config{LDAPHOST} eq $config{HOSTNAME} ) {
           runAsZextras ("/opt/zextras/bin/zmldappasswd $config{LDAPADMINPASS}");
         } else {
           setLocalConfig ("zimbra_ldap_password", "$config{LDAPADMINPASS}");
         }
         progress ( "done.\n" );
      }
      if ($ldapRepChanged == 1) {
         progress ( "Setting replication password..." );
         if ($config{LDAPHOST} eq $config{HOSTNAME} ) {
           runAsZextras ("/opt/zextras/bin/zmldappasswd -l $config{LDAPREPPASS}");
         } else {
           setLocalConfig ("ldap_replication_password", "$config{LDAPREPPASS}");
         }
         progress ( "done.\n" );
      }
      if ($ldapPostChanged == 1) {
         progress ( "Setting Postfix password..." );
         if ($config{LDAPHOST} eq $config{HOSTNAME} ) {
           runAsZextras ("/opt/zextras/bin/zmldappasswd -p $config{LDAPPOSTPASS}");
         } else {
           setLocalConfig ("ldap_postfix_password", "$config{LDAPPOSTPASS}");
         }
         progress ( "done.\n" );
      }
      if ($ldapAmavisChanged == 1) {
         progress ( "Setting amavis password..." );
         if ($config{LDAPHOST} eq $config{HOSTNAME} ) {
           runAsZextras ("/opt/zextras/bin/zmldappasswd -a $config{LDAPAMAVISPASS}");
         } else {
           setLocalConfig ("ldap_amavis_password", "$config{LDAPAMAVISPASS}");
        }
         progress ( "done.\n" );
      }
      if ($ldapNginxChanged == 1) {
         progress ( "Setting nginx password..." );
         if ($config{LDAPHOST} eq $config{HOSTNAME} ) {
           runAsZextras ("/opt/zextras/bin/zmldappasswd -n $config{ldap_nginx_password}");
         } else {
           setLocalConfig ("ldap_nginx_password", "$config{ldap_nginx_password}");
        }
         progress ( "done.\n" );
      }
    } else {
      progress("Stopping ldap...");
      runAsZextras ("/opt/zextras/bin/ldap stop");
      progress("done.\n");
      startLdap();
    }


  } else {
    detail("Updating ldap user passwords\n");
    setLocalConfig ("ldap_root_password", $config{LDAPROOTPASS});
    setLocalConfig ("zimbra_ldap_password", $config{LDAPADMINPASS});
    setLocalConfig ("ldap_replication_password", "$config{LDAPREPPASS}");
    setLocalConfig ("ldap_postfix_password", "$config{LDAPPOSTPASS}");
    setLocalConfig ("ldap_amavis_password", "$config{LDAPAMAVISPASS}");
    setLocalConfig ("ldap_nginx_password", "$config{ldap_nginx_password}");
  }

  configLog("configSetupLdap");
  return 0;

}

sub configLDAPSchemaVersion {
  return if ($haveSetLdapSchemaVersion);
  if (isEnabled("carbonio-directory-server")) {
    progress ("Updating LDAP Schema version to '$ldapSchemaVersion'\n");
    setLdapGlobalConfig('zimbraLDAPSchemaVersion', $ldapSchemaVersion);
    $haveSetLdapSchemaVersion = 1;
  }
}

sub configSaveCA {

  if ($configStatus{configSaveCA} eq "CONFIGURED") {
    configLog("configSaveCA");
    return 0;
  }
  progress ( "Saving CA in ldap..." );
  my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deployca");
  if ($rc != 0) {
    progress ( "failed.\n" );
    exit 1;
  } else {
    progress ( "done.\n" );
  }
  configLog("configSaveCA");
}

sub configCreateCert {

  if ($configStatus{configCreateCert} eq "CONFIGURED" && -d "/opt/zextras/ssl/carbonio/server") {
    configLog("configCreateCert");
    return 0;
  }

  if (!$newinstall) {
    my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt comm > /dev/null 2>&1");
    if ($rc != 0) {
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr verifycrt self > /dev/null 2>&1");
      if ($rc != 0) {
        progress("Warning: No valid SSL certificates were found.\n");
        progress("New self-signed certificates will be generated and installed.\n");
        $needNewCert = "-new" if ($rc != 0);
        $ssl_cert_type="self";
      }
    } else {
      $ssl_cert_type="comm";
      $needNewCert="";
    }
  }

  my $rc;

  if (isInstalled("carbonio-appserver")) {
    if ( !-f "$config{mailboxd_keystore}" && !-f "/opt/zextras/ssl/carbonio/server/server.crt" ) {
      if (!-d "$config{mailboxd_directory}") {
        qx(mkdir -p $config{mailboxd_directory}/etc);
        qx(chown -R zextras:zextras $config{mailboxd_directory});
        qx(chmod 744 $config{mailboxd_directory}/etc);
      }
      progress ( "Creating SSL carbonio-appserver certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    } elsif ( $needNewCert ne "" && $ssl_cert_type eq "self") {
      progress ( "Creating new carbonio-appserver SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    }
  }

  if (isInstalled("carbonio-directory-server")) {
    if ( !-f "/opt/zextras/conf/slapd.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt") {
      progress ( "Creating carbonio-directory-server SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    } elsif ( $needNewCert ne "" && $ssl_cert_type eq "self") {
      progress ( "Creating new carbonio-directory-server SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    }
  }

  if (isInstalled("carbonio-mta")) {
    if ( !-f "/opt/zextras/conf/smtpd.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt") {
      progress ( "Creating carbonio-mta SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    } elsif ( $needNewCert ne "" && $ssl_cert_type eq "self") {
      progress ( "Creating new carbonio-mta SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    }
  }

  if (isInstalled("carbonio-proxy")) {
    if ( !-f "/opt/zextras/conf/nginx.crt" && !-f "/opt/zextras/ssl/carbonio/server/server.crt") {
      progress ( "Creating carbonio-proxy SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    } elsif ( $needNewCert ne "" && $ssl_cert_type eq "self") {
      progress ( "Creating new carbonio-proxy SSL certificate..." );
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr createcrt $needNewCert");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
      }
    }
  }

  configLog("configCreateCert");
}

sub configSaveCert {

  if ($configStatus{configSaveCert} eq "CONFIGURED") {
    configLog("configSaveCert");
    return 0;
  }
  progress ( "Saving SSL Certificate in ldap..." );
  my $rc = runAsZextras("/opt/zextras/bin/zmcertmgr savecrt $ssl_cert_type");
  if ($rc != 0) {
    progress ( "failed.\n" );
    exit 1;
  } else {
    progress ( "done.\n" );
  }
  configLog("configSaveCert");
}

sub configInstallCert {
  my $rc;
  if ($configStatus{configInstallCertStore} eq "CONFIGURED" && $needNewCert eq "") {
    configLog("configInstallCertStore");
  } elsif (isInstalled("carbonio-appserver")) {
    if (! (-f "$config{mailboxd_keystore}") || $needNewCert ne "") {
      progress ("Installing mailboxd SSL certificates...");
      detail("$config{mailboxd_keystore} didn't exist.")
        if (! -f "$config{mailboxd_keystore}");
      detail("$needNewCert was ne \"\".")
        if ($needNewCert ne "");
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $ssl_cert_type");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
        configLog("configInstallCertStore");
      }
    } else {
      configLog("configInstallCertStore");
    }
  }

  if ($configStatus{configInstallCertMTA} eq "CONFIGURED" && $needNewCert eq "") {
    configLog("configInstallCertMTA");
  } elsif (isInstalled("carbonio-mta")) {

    if (! (-f "/opt/zextras/conf/smtpd.key" ||
      -f "/opt/zextras/conf/smtpd.crt" ) || $needNewCert ne "")  {
      progress ("Installing MTA SSL certificates...");
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $ssl_cert_type");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
        configLog("configInstallCertMTA");
      }
    } else {
      configLog("configInstallCertMTA");
    }
  }

  if ($configStatus{configInstallCertLDAP} eq "CONFIGURED" && $needNewCert eq "") {
    configLog("configInstallCertLDAP");
  } elsif (isInstalled("carbonio-directory-server")) {
    if (! (-f "/opt/zextras/conf/slapd.key" ||
      -f "/opt/zextras/conf/slapd.crt" ) || $needNewCert ne "") {
      progress ("Installing LDAP SSL certificate...");
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $ssl_cert_type");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
        stopLdap() if ($ldapConfigured);
        startLdap() if ($ldapConfigured);
        configLog("configInstallCertLDAP");
      }
    } else {
      configLog("configInstallCertLDAP");
    }
  }

  if ($configStatus{configInstallCertProxy} eq "CONFIGURED" && $needNewCert eq "") {
    configLog("configInstallCertProxy");
  } elsif (isInstalled("carbonio-proxy")) {
    if (! (-f "/opt/zextras/conf/nginx.key" ||
      -f "/opt/zextras/conf/nginx.crt")  || $needNewCert ne "") {
      progress ("Installing Proxy SSL certificate...");
      $rc = runAsZextras("/opt/zextras/bin/zmcertmgr deploycrt $ssl_cert_type");
      if ($rc != 0) {
        progress ( "failed.\n" );
        exit 1;
      } else {
        progress ( "done.\n" );
        configLog("configInstallCertProxy");
      }
    } else {
      configLog("configInstallCertProxy");
    }
  }

}

sub configCreateServerEntry {

  if ($configStatus{configCreateServerEntry} eq "CONFIGURED") {
    configLog("configCreateServerEntry");
    return 0;
  }

  progress ( "Creating server entry for $config{HOSTNAME}..." );
  my $serverId = getLdapServerValue("zimbraId");
  if ($serverId ne "") {
    progress("already exists.\n");
  } else {
    my $rc = runAsZextras("$ZMPROV cs $config{HOSTNAME}");
    progress(($rc == 0) ? "done.\n" : "failed.\n");
  }
  progress ( "Setting IP Mode..." );
  my $rc = setLdapServerConfig("zimbraIPMode", $config{zimbraIPMode});
  progress(($rc == 0) ? "done.\n" : "failed.\n");
  my $rc = runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

  configLog("configCreateServerEntry");
}

sub configSetStoreDefaults {
  if(isEnabled("carbonio-proxy") || $config{zimbraMailProxy} eq "TRUE" || $config{zimbraWebProxy} eq "TRUE") {
    $config{zimbraReverseProxyLookupTarget}="TRUE";
  }
  # for mailstore split, set zimbraReverseProxyAvailableLookupTargets on service-only nodes
  if ($newinstall && isStoreServiceNode()) {
	my $adding=0;
	progress("Checking current setting of ReverseProxyAvailableLookupTargets\n");
	my $zrpALT = getLdapConfigValue("zimbraReverseProxyAvailableLookupTargets");
	if ($zrpALT ne "") {
	  $adding=1;
	} else {
	  progress("Querying LDAP for other mailstores\n");
	  # query LDAP to see if there are other mailstores.  If there are none, add this
	  # new service node to zimbraReverseProxyAvailableLookupTargets.  Otherwise do not
	  my $count = countReverseProxyLookupTargets();
	  if (!defined($count) || $count == 0) {
		$adding=1;
	  }
	}
	if ($adding) {
	  progress("Adding $config{HOSTNAME} to ReverseProxyAvailableLookupTargets\n");
	  setLdapGlobalConfig("+zimbraReverseProxyAvailableLookupTargets", $config{HOSTNAME});
	}
  }
  $config{zimbraMtaAuthTarget}="TRUE";
  if (!isStoreServiceNode()) {
    $config{zimbraMtaAuthTarget}="FALSE";
  }
  if ($newinstall && isStoreServiceNode()) {
    setLdapGlobalConfig("+zimbraReverseProxyUpstreamEwsServers", "$config{HOSTNAME}");
  }
  if ($newinstall && isStoreWebNode()) {
    setLdapGlobalConfig("+zimbraReverseProxyUpstreamLoginServers", "$config{HOSTNAME}");
  }
  setLdapServerConfig("zimbraReverseProxyLookupTarget", $config{zimbraReverseProxyLookupTarget});
  setLdapServerConfig("zimbraMtaAuthTarget", $config{zimbraMtaAuthTarget});
  my $upstream="-u";
  if ($config{zimbra_require_interprocess_security}) {
    $upstream="-U";
  }
  if ($newinstall && ($config{zimbraWebProxy} eq "TRUE" || $config{zimbraMailProxy} eq "TRUE")) {
      if ($config{zimbraMailProxy} eq "TRUE") {
           runAsZextras("/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o ".
                       "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} ".
                       "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}");
    }
    if ($config{zimbraWebProxy} eq "TRUE") {
           runAsZextras("/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o ".
                       "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}");
    }
  }
}

sub isStoreWebNode {
    if ($installedWebapps{"zimbra"} eq "Enabled" || $installedWebapps{"zimbraAdmin"} eq "Enabled") {
        return 1;
    } else {
        return 0;
    }
}

sub isStoreServiceNode {
    if ($installedWebapps{"service"} eq "Enabled") {
        return 1;
    } else {
        return 0;
    }
}

sub configSetServicePorts {

  if ($configStatus{configSetServicePorts} eq "CONFIGURED") {
    configLog("configSetServicePorts");
    return 0;
  }

  progress ( "Setting service ports on $config{HOSTNAME}..." );
  if ($config{MAILPROXY} eq "FALSE") {
    if ($config{IMAPPORT} == 7143 && $config{IMAPPROXYPORT} == $config{IMAPPORT}) {
      $config{IMAPPROXYPORT} = 143;
    }
    if ($config{IMAPSSLPORT} == 7993 && $config{IMAPSSLPROXYPORT} == $config{IMAPSSLPORT}) {
      $config{IMAPSSLPROXYPORT} = 993;
    }
    if ($config{POPPORT} == 7110 && $config{POPPROXYPORT} == $config{POPPORT}) {
      $config{POPPROXYPORT} = 110;
    }
    if ($config{POPSSLPORT} == 7995 && $config{POPSSLPROXYPORT} == $config{POPSSLPORT}) {
      $config{POPSSLPORT} = 995;
    }
  }
  setLdapServerConfig($config{HOSTNAME},
    "zimbraImapBindPort", $config{IMAPPORT},
    "zimbraImapSSLBindPort", $config{IMAPSSLPORT},
    "zimbraImapProxyBindPort", $config{IMAPPROXYPORT},
    "zimbraImapSSLProxyBindPort", $config{IMAPSSLPROXYPORT}
	);
  setLdapServerConfig($config{HOSTNAME},
    "zimbraPop3BindPort", $config{POPPORT},
    "zimbraPop3SSLBindPort", $config{POPSSLPORT},
    "zimbraPop3ProxyBindPort", $config{POPPROXYPORT},
    "zimbraPop3SSLProxyBindPort", $config{POPSSLPROXYPORT}
    );
  if ($config{HTTPPROXY} eq "FALSE") {
    if ($config{HTTPPORT} == 8080 && $config{HTTPPROXYPORT} == $config{HTTPPORT}) {
      $config{HTTPPROXYPORT} = 80;
    }
    if ($config{HTTPSPORT} == 8443 && $config{HTTPSPROXYPORT} == $config{HTTPSPORT}){
      $config{HTTPSPROXYPORT} = 443;
    }
  }
  setLdapServerConfig($config{HOSTNAME},
    "zimbraMailPort", $config{HTTPPORT},
    "zimbraMailSSLPort", $config{HTTPSPORT},
    "zimbraMailProxyPort", $config{HTTPPROXYPORT},
    "zimbraMailSSLProxyPort", $config{HTTPSPROXYPORT},
    "zimbraMailMode", $config{MODE}
    );
  setLocalConfig("zimbra_mail_service_port", $config{HTTPPORT});

  progress ( "done.\n" );
  configLog("configSetServicePorts");
}

sub configSetKeyboardShortcutsPref {
  if ($configStatus{zimbraPrefUseKeyboardShortcuts} eq "CONFIGURED") {
    configLog("zimbraPrefUseKeyboardShortcuts");
    return 0;
  }
  progress ( "Setting Keyboard Shortcut Preferences...");
  my $rc = setLdapCOSConfig("zimbraPrefUseKeyboardShortcuts", $config{USEKBSHORTCUTS});
  progress (($rc == 0) ? "done.\n" : "failed.\n");
  configLog("zimbraPrefUseKeyboardShortcuts");
}

sub configSetTimeZonePref {
  if ($configStatus{zimbraPrefTimeZoneId} eq "CONFIGURED") {
    configLog("zimbraPrefTimeZoneId");
    return 0;
  }
  if($config{LDAPHOST} eq $config{HOSTNAME}) {
    progress ( "Setting TimeZone Preference...");
    my $rc = setLdapCOSConfig("zimbraPrefTimeZoneId", $config{zimbraPrefTimeZoneId});
    progress (($rc == 0) ? "done.\n" : "failed.\n");
  }
  configLog("zimbraPrefTimeZoneId");
}

sub setProxyBits {
  detail("Setting Proxy pieces\n");
  my $zimbraReverseProxyMailHostQuery =
        "\(\|\(zimbraMailDeliveryAddress=\${USER}\)\(zimbraMailAlias=\${USER}\)\(zimbraId=\${USER}\)\)";
  my $zimbraReverseProxyDomainNameQuery =
        '\(\&\(zimbraVirtualIPAddress=\${IPADDR}\)\(objectClass=zimbraDomain\)\)';
  my $zimbraReverseProxyPortQuery =
        '\(\&\(zimbraServiceHostname=\${MAILHOST}\)\(objectClass=zimbraServer\)\)';

  my @zmprov_args = ();
  push(@zmprov_args, ('zimbraReverseProxyMailHostQuery', $zimbraReverseProxyMailHostQuery))
    if(getLdapConfigValue("zimbraReverseProxyMailHostQuery") eq "");

  push(@zmprov_args, ('zimbraReverseProxyPortQuery', $zimbraReverseProxyPortQuery))
    if(getLdapConfigValue("zimbraReverseProxyPortQuery") eq "");

  push(@zmprov_args, ('zimbraReverseProxyDomainNameQuery', $zimbraReverseProxyDomainNameQuery))
    if(getLdapConfigValue("zimbraReverseProxyDomainNameQuery") eq "");

  push(@zmprov_args, ('zimbraMemcachedBindPort', '11211'))
    if(getLdapConfigValue("zimbraMemcachedBindPort") eq "");

  push(@zmprov_args, ('zimbraMemcachedBindAddress', '127.0.0.1'))
    if(getLdapConfigValue("zimbraMemcachedBindAddress") eq "");

  push(@zmprov_args, ('zimbraReverseProxyMailHostAttribute', 'zimbraMailHost'))
    if(getLdapConfigValue("zimbraReverseProxyMailHostAttribute") eq "");

  push(@zmprov_args, ('zimbraReverseProxyPop3PortAttribute', 'zimbraPop3BindPort'))
    if(getLdapConfigValue("zimbraReverseProxyPop3PortAttribute") eq "");

  push(@zmprov_args, ('zimbraReverseProxyPop3SSLPortAttribute', 'zimbraPop3SSLBindPort'))
    if(getLdapConfigValue("zimbraReverseProxyPop3SSLPortAttribute") eq "");

  push(@zmprov_args, ('zimbraReverseProxyImapPortAttribute', 'zimbraImapBindPort'))
    if(getLdapConfigValue("zimbraReverseProxyImapPortAttribute") eq "");

  push(@zmprov_args, ('zimbraReverseProxyImapSSLPortAttribute', 'zimbraImapSSLBindPort'))
    if(getLdapConfigValue("zimbraReverseProxyImapSSLPortAttribute") eq "");

  push(@zmprov_args, ('zimbraReverseProxyDomainNameAttribute', 'zimbraDomainName'))
    if(getLdapConfigValue("zimbraReverseProxyDomainNameAttribute") eq "");

  push(@zmprov_args, ('zimbraImapCleartextLoginEnabled', 'FALSE'))
    if(getLdapConfigValue("zimbraImapCleartextLoginEnabled") eq "");

  push(@zmprov_args, ('zimbraPop3CleartextLoginEnabled', 'FALSE'))
    if(getLdapConfigValue("zimbraPop3CleartextLoginEnabled") eq "");

  push(@zmprov_args, ('zimbraReverseProxyAuthWaitInterval', '10s'))
    if(getLdapConfigValue("zimbraReverseProxyAuthWaitInterval") eq "");

  push(@zmprov_args, ('zimbraReverseProxyIPLoginLimit', '0'))
    if(getLdapConfigValue("zimbraReverseProxyIPLoginLimit") eq "");

  push(@zmprov_args, ('zimbraReverseProxyIPLoginLimitTime', '3600'))
    if(getLdapConfigValue("zimbraReverseProxyIPLoginLimitTime") eq "");

  push(@zmprov_args, ('zimbraReverseProxyUserLoginLimit', '0'))
    if(getLdapConfigValue("zimbraReverseProxyUserLoginLimit") eq "");

  push(@zmprov_args, ('zimbraReverseProxyUserLoginLimitTime', '3600'))
    if(getLdapConfigValue("zimbraReverseProxyUserLoginLimitTime") eq "");

  push(@zmprov_args, ('zimbraMailProxyPort', '0'))
    if(getLdapConfigValue("zimbraMailProxyPort") eq "");

  push(@zmprov_args, ('zimbraMailSSLProxyPort', '0'))
    if(getLdapConfigValue("zimbraMailSSLProxyPort") eq "");

  push(@zmprov_args, ('zimbraReverseProxyHttpEnabled', 'FALSE'))
    if(getLdapConfigValue("zimbraReverseProxyHttpEnabled") eq "");

  push(@zmprov_args, ('zimbraReverseProxyMailEnabled', 'TRUE'))
    if(getLdapConfigValue("zimbraReverseProxyMailEnabled") eq "");

  setLdapGlobalConfig( @zmprov_args );

}

sub configSetProxyPrefs {
   if (isEnabled("carbonio-proxy")) {
     if ($config{STRICTSERVERNAMEENABLED} eq "yes") {
        progress("Enabling strict server name enforcement on $config{HOSTNAME}...");
        runAsZextras("$ZMPROV ms $config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled TRUE");
        progress("done.\n");
     } else {
        progress("Disabling strict server name enforcement on $config{HOSTNAME}...");
        runAsZextras("$ZMPROV ms $config{HOSTNAME} zimbraReverseProxyStrictServerNameEnabled FALSE");
        progress("done.\n");
     }
     if ($config{MAILPROXY} eq "FALSE" && $config{HTTPPROXY} eq "FALSE") {
        $enabledPackages{"carbonio-proxy"} = "Disabled";
     } else {
       my $upstream="-u";
       if ($config{zimbra_require_interprocess_security}) {
         $upstream="-U";
       }
       if($config{MAILPROXY} eq "TRUE") {
         runAsZextras("/opt/zextras/libexec/zmproxyconfig $upstream -m -e -o ".
                     "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} ".
                     "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}");
       } else {
         runAsZextras("/opt/zextras/libexec/zmproxyconfig -m -d -o ".
                     "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} ".
                     "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}");
       }
       if ($config{HTTPPROXY} eq "TRUE" ) {
         runAsZextras("/opt/zextras/libexec/zmproxyconfig $upstream -w -e -o ".
                     " -x $config{PROXYMODE} ".
                     "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}");
       } else {
         runAsZextras("/opt/zextras/libexec/zmproxyconfig -w -d -o ".
                     "-x $config{MODE} ".
                     "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}");
       }
     }
     if (!(isEnabled("carbonio-appserver"))) {
       my @storetargets;
       detail("Running $ZMPROV garpu");
       open(ZMPROV, "$ZMPROV garpu 2>/dev/null|");
       chomp(@storetargets = <ZMPROV>);
       close(ZMPROV);
       if ( $storetargets[0] !~ /nginx-lookup/ ) {
         progress("WARNING: There is currently no mailstore to proxy. Proxy will restart once one becomes available.\n");
       }
     }
     if (!(isEnabled("carbonio-memcached"))) {
       my @memcachetargets;
       detail("Running $ZMPROV gamcs");
       open(ZMPROV, "$ZMPROV gamcs 2>/dev/null|");
       chomp(@memcachetargets = <ZMPROV>);
       close(ZMPROV);
       if ( $memcachetargets[0] !~ /:11211/ ) {
         progress("WARNING: There are currently no memcached servers for the proxy.  Proxy will start once one becomes available.\n");
       }
     }
   } else {
     runAsZextras("/opt/zextras/libexec/zmproxyconfig -m -d -o ".
                 "-i $config{IMAPPORT}:$config{IMAPPROXYPORT}:$config{IMAPSSLPORT}:$config{IMAPSSLPROXYPORT} ".
                 "-p $config{POPPORT}:$config{POPPROXYPORT}:$config{POPSSLPORT}:$config{POPSSLPROXYPORT} -H $config{HOSTNAME}");
     runAsZextras("/opt/zextras/libexec/zmproxyconfig -w -d -o ".
                 "-x $config{MODE} ".
                 "-a $config{HTTPPORT}:$config{HTTPPROXYPORT}:$config{HTTPSPORT}:$config{HTTPSPROXYPORT} -H $config{HOSTNAME}");
   }
}

sub countReverseProxyLookupTargets {
  my $count = 0;
  my $ldap_pass = getLocalConfig("zimbra_ldap_password");
  my $ldap_master_url = getLocalConfig("ldap_master_url");
  my $ldap;
  my @masters=split(/ /, $ldap_master_url);
  my $master_ref=\@masters;

  unless($ldap = Net::LDAP->new($master_ref)) {
    detail("Unable to contact $ldap_master_url: $!");
    return;
  }
  my $ldap_dn = $config{zimbra_ldap_userdn};
  my $ldap_base = "";

  my $result = $ldap->bind($ldap_dn, password => $ldap_pass);
  if ($result->code()) {
    detail("ldap bind failed for $ldap_dn");
    return;
  } else {
    detail("ldap bind done for $ldap_dn");
    progress("Searching LDAP for reverseProxyLookupTargets...");
    $result = $ldap->search(base => 'cn=zimbra', filter => '(zimbraReverseProxyLookupTarget=TRUE)', attrs => ['1.1']);

    progress (($result->code()) ? "failed.\n" : "done.\n");
    return if ($result->code());
    $count = $result->count;
  }
  return "$count";
}

sub countUsers {
  return $main::loaded{stats}{numAccts}
    if (exists $main::loaded{stats}{numAccts});
  my $count = 0;
  my $ldap_pass = getLocalConfig("zimbra_ldap_password");
  my $ldap_master_url = getLocalConfig("ldap_master_url");
  my $ldap;
  my @masters=split(/ /, $ldap_master_url);
  my $master_ref=\@masters;
  unless($ldap = Net::LDAP->new($master_ref)) {
    detail("Unable to contact $ldap_master_url: $!");
    return undef;
  }
  my $ldap_dn = $config{zimbra_ldap_userdn};
  my $ldap_base = "";

  my $result = $ldap->bind($ldap_dn, password => $ldap_pass);
  if ($result->code()) {
    detail("ldap bind failed for $ldap_dn");
    return undef;
  } else {
    detail("ldap bind done for $ldap_dn");
    progress("Searching LDAP for zimbra accounts...");
    $result = $ldap->search(filter => "(objectclass=zimbraAccount)", \
      attrs => ['zimbraMailDeliveryAddress']);
    progress (($result->code()) ? "failed.\n" : "done.\n");
    return undef if ($result->code());
    $count = $result->count;
  }
  $result = $ldap->unbind;
  $main::loaded{stats}{numAccts} = $count
    if ($count > 0);
  return(($count > 0) ? "$count" : undef);
}


sub zimletCleanup {
  my $ldap_pass = getLocalConfig("zimbra_ldap_password");
  my $ldap_master_url = getLocalConfig("ldap_master_url");
  my $ldap;
  my @masters=split(/ /, $ldap_master_url);
  my $master_ref=\@masters;
  unless($ldap = Net::LDAP->new($master_ref)) {
    detail("Unable to contact $ldap_master_url: $!");
    return 1;
  }
  my $ldap_dn = $config{zimbra_ldap_userdn};
  my $ldap_base = "cn=zimlets,$config{ldap_dit_base_dn_config}";

  my $result = $ldap->bind($ldap_dn, password => $ldap_pass);
  if ($result->code()) {
    detail("ldap bind failed for $ldap_dn");
    return 1;
  } else {
    detail("ldap bind done for $ldap_dn");
    $result = $ldap->search(base => $ldap_base, scope => 'one', filter => "(|(cn=zimbra_cert_manager)(cn=com_zimbra_search)(cn=com_zimbra_domainadmin)(cn=com_zimbra_tinymce)(cn=com_zimbra_tasksreminder)(cn=com_zimbra_linkedin)(cn=com_zimbra_social)(cn=com_zimbra_dnd)(cn=com_zextras_chat_open)(cn=com_zextras_talk))", attrs => ['cn']);
    return $result if ($result->code());
    detail("Processing ldap search results");
    foreach my $entry ($result->all_entries) {
      my $zimlet = $entry->get_value('cn');
      if ( $zimlet ne "" ) {
        detail("Removing $zimlet");
        runAsZextras("/opt/zextras/bin/zmzimletctl -l undeploy $zimlet");
        system("rm -rf $config{mailboxd_directory}/webapps/service/zimlet/$zimlet")
          if (-d "$config{mailboxd_directory}/webapps/service/zimlet/$zimlet" );
      }
    }
  }
  $result = $ldap->unbind;
  return 0;
}

sub configInstallZimlets {

  if ($configStatus{configInstallZimlets} eq "CONFIGURED") {
    configLog("configInstallZimlets");
    return 0;
  }

  my $zimlet_directory = getLocalConfig("zimlet_directory") || "/opt/zextras/zimlets-deployed";
  my $zimlet_properties = getLocalConfig("zimlet_properties_directory") || "/opt/zextras/zimlets-properties";
  my (undef,undef,$uid,$gid) = getpwnam("zextras");

  mkdir($zimlet_directory)
    if (! -d $zimlet_directory);
  chown($uid,$gid, $zimlet_directory);
  chmod(0755, $zimlet_directory);

  system("/bin/rm -rf $zimlet_properties")
    if ( -d $zimlet_properties);

  # remove deprecated zimlets on upgrades
  if (!$newinstall) {
    progress("Checking for deprecated zimlets...");
    progress((zimletCleanup()) ? "failed.\n" : "done.\n");
  }

  # Install zimlets
  if (opendir DIR, "/opt/zextras/zimlets") {
    progress ( "Installing common zimlets...\n" );
    my @core_zimlets = (qw(com_zimbra_dnd com_zimbra_url com_zimbra_date com_zimbra_email com_zimbra_attachcontacts com_zimbra_attachmail));
    my @zimlets = grep { !/^\./ } readdir(DIR);
    foreach my $zimletfile (@zimlets) {
      my $zimlet = $zimletfile;
      $zimlet =~ s/\.zip$//;
      progress  ("\t$zimlet...");
      my $rc = runAsZextras ("/opt/zextras/bin/zmzimletctl -l deploy zimlets/$zimletfile");
      if ($rc == 0) {
        setLdapCOSConfig("+zimbraZimletAvailableZimlets", "!$zimlet")
          if (grep(/$zimlet/, @core_zimlets));
        progress("done.\n");
      } else {
        progress("failed. This may impact system functionality.\n");
      }

    }
    progress ( "Finished installing common zimlets.\n" );
  }

  # Reinstall extras that are deployed on upgrade
  if (!$newinstall) {
    my $ldap_pass = getLocalConfig("zimbra_ldap_password");
    my $ldap_master_url = getLocalConfig("ldap_master_url");
    my $ldap;
    my @masters=split(/ /, $ldap_master_url);
    my $master_ref=\@masters;
    unless($ldap = Net::LDAP->new($master_ref)) {
      detail("Unable to contact $ldap_master_url: $!");
      return 1;
    }
    my $ldap_dn = $config{zimbra_ldap_userdn};
    my $ldap_base = "cn=zimlets,$config{ldap_dit_base_dn_config}";

    my $result = $ldap->bind($ldap_dn, password => $ldap_pass);
    if ($result->code()) {
      detail("ldap bind failed for $ldap_dn");
      return 1;
    } else {
      detail("ldap bind done for $ldap_dn");
      progress("Getting list of all zimlets...");
      $result = $ldap->search(base => $ldap_base, scope => 'one', filter => '(objectClass=zimbraZimletEntry)', attrs => ['cn']);
      progress (($result->code()) ? "failed.\n" : "done.\n");
      return $result if ($result->code());

      progress("Updating non-standard zimlets...\n");
      foreach my $entry ($result->all_entries) {
        my $zimlet = $entry->get_value('cn');
        foreach my $type (qw(zimlets-admin-extra zimlets-experimental zimlets-extra)) {
          if (-e "/opt/zextras/${type}/${zimlet}.zip") {
           progress  ("\t$zimlet...");
           my $rc = runAsZextras ("/opt/zextras/bin/zmzimletctl -l deploy ${type}/${zimlet}.zip");
           progress (($rc == 0) ? "done.\n" : "failed. This may impact system functionality.\n");
          }
        }
      }
      progress("Finished updating non-standard zimlets.\n");
    $result = $ldap->unbind;
    }
  }

  configLog("configInstallZimlets");
}

sub configCreateDomain {

  if ($configStatus{configCreateDomain} eq "CONFIGURED") {
    configLog("configCreateDomain");
    return 0;
  }

  if (!$ldapConfigured && isEnabled("carbonio-directory-server")) {
    if ($config{DOCREATEDOMAIN} eq "yes") {
      progress ( "Creating domain $config{CREATEDOMAIN}..." );
      my $domainId = getLdapDomainValue("zimbraId");
      if ($domainId ne "") {
        progress("already exists.\n");
      } else {
        my $rc = runAsZextras("$ZMPROV cd $config{CREATEDOMAIN}");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      progress("Setting default domain name...");
      my $rc = setLdapGlobalConfig("zimbraDefaultDomainName", $config{CREATEDOMAIN});
      progress("Setting value of postfix myorigin...");
      my $rc = setLdapGlobalConfig("zimbraMtaMyOrigin", $config{CREATEDOMAIN});
      progress(($rc == 0) ? "done.\n" : "failed.\n");
    }
  }
  if (isEnabled("carbonio-appserver")) {
    if ($config{DOCREATEADMIN} eq "yes") {
      $config{CREATEADMIN} = lc($config{CREATEADMIN});
      my ($u,$d) = split ('@', $config{CREATEADMIN});

      progress ("Creating domain $d...");
      my $domainId = getLdapDomainValue("zimbraId",$d);
      if ($domainId ne "") {
        progress("already exists.\n");
      } else {
        my $rc = runAsZextras("$ZMPROV cd $d");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      progress ("Creating admin account $config{CREATEADMIN}...");
      my $acctId = getLdapAccountValue("zimbraId", $config{CREATEADMIN});
      if ($acctId ne "") {
        progress("already exists.\n");
      } else {
        my $rc = runAsZextras("$ZMPROV ca ".
          "$config{CREATEADMIN} \'$config{CREATEADMINPASS}\' ".
          "zimbraAdminConsoleUIComponents cartBlancheUI ".
          "description \'Administrative Account\' ".
          "zimbraIsAdminAccount TRUE");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      # no root/postmaster accounts on web-only nodes
      if (isStoreServiceNode()) {
        progress ( "Creating root alias..." );
        my $rc = runAsZextras("$ZMPROV aaa ".
            "$config{CREATEADMIN} root\@$config{CREATEDOMAIN}");
        progress(($rc == 0) ? "done.\n" : "failed.\n");

        progress ( "Creating postmaster alias..." );
        $rc = runAsZextras("$ZMPROV aaa ".
            "$config{CREATEADMIN} postmaster\@$config{CREATEDOMAIN}");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

    }

    if ($config{DOTRAINSA} eq "yes") {
      $config{TRAINSASPAM} = lc($config{TRAINSASPAM});
      progress ( "Creating user $config{TRAINSASPAM}..." );
      my $acctId = getLdapAccountValue("zimbraId", $config{TRAINSASPAM});
      if ($acctId ne "") {
        progress("already exists.\n");
      } else {
        my $pass = genRandomPass();
        my $rc = runAsZextras("$ZMPROV ca ".
          "$config{TRAINSASPAM} \'$pass\' ".
          "amavisBypassSpamChecks TRUE ".
          "zimbraAttachmentsIndexingEnabled FALSE ".
          "zimbraIsSystemResource TRUE ".
          "zimbraIsSystemAccount TRUE ".
          "zimbraHideInGal TRUE ".
          "zimbraMailQuota 0 ".
          "description \'System account for spam training.\'");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      $config{TRAINSAHAM} = lc($config{TRAINSAHAM});
      progress ( "Creating user $config{TRAINSAHAM}..." );
      my $acctId = getLdapAccountValue("zimbraId", $config{TRAINSAHAM});
      if ($acctId ne "") {
        progress("already exists.\n");
      } else {
        my $pass = genRandomPass();
        my $rc = runAsZextras("$ZMPROV ca ".
          "$config{TRAINSAHAM} \'$pass\' ".
          "amavisBypassSpamChecks TRUE ".
          "zimbraAttachmentsIndexingEnabled FALSE ".
          "zimbraIsSystemResource TRUE ".
          "zimbraIsSystemAccount TRUE ".
          "zimbraHideInGal TRUE ".
          "zimbraMailQuota 0 ".
          "description \'System account for Non-Spam (Ham) training.\'");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      $config{VIRUSQUARANTINE} = lc($config{VIRUSQUARANTINE});
      progress ( "Creating user $config{VIRUSQUARANTINE}..." );
      my $acctId = getLdapAccountValue("zimbraId", $config{VIRUSQUARANTINE});
      if ($acctId ne "") {
        progress("already exists.\n");
      } else {
        my $pass = genRandomPass();
        my $rc = runAsZextras("$ZMPROV ca ".
          "$config{VIRUSQUARANTINE} \'$pass\' ".
          "amavisBypassSpamChecks TRUE ".
          "zimbraAttachmentsIndexingEnabled FALSE ".
          "zimbraIsSystemResource TRUE ".
          "zimbraIsSystemAccount TRUE ".
          "zimbraHideInGal TRUE ".
          "zimbraMailMessageLifetime 30d ".
          "zimbraMailQuota 0 ".
          "description \'System account for Anti-virus quarantine.\'");
        progress(($rc == 0) ? "done.\n" : "failed.\n");
      }

      progress ( "Setting spam training and Anti-virus quarantine accounts..." );
      my $rc = setLdapGlobalConfig(
        'zimbraSpamIsSpamAccount', "$config{TRAINSASPAM}",
        'zimbraSpamIsNotSpamAccount', "$config{TRAINSAHAM}",
        'zimbraAmavisQuarantineAccount', "$config{VIRUSQUARANTINE}"
        );
      progress(($rc == 0) ? "done.\n" : "failed.\n");
    }
  }
  configLog("configCreateDomain");
}

sub configInitSql {

  if ($configStatus{configInitSql} eq "CONFIGURED") {
    configLog("configInitSql");
    return 0;
  }

  if (!$sqlConfigured && isEnabled("carbonio-appserver")) {
    progress ( "Initializing store sql database..." );
    runAsZextras ("/opt/zextras/libexec/zmmyinit --mysql_memory_percent $config{MYSQLMEMORYPERCENT}");
    progress ( "done.\n" );
    progress ( "Setting SmtpHostname for $config{HOSTNAME}..." );

    #SMTP host can be one or more values seperated by comma or space.
    my @smtphost = split /[,\s]+/, $config{SMTPHOST};
    foreach(@smtphost) {
       my $rc = setLdapServerConfig("+zimbraSmtpHostname", $_);
       progress(($rc == 0) ? "done.\n" : "failed.\n");
    }
  }
  configLog("configInitSql");
}

sub configInitLogger {

  if ($configStatus{configInitLogger} eq "CONFIGURED") {
    configLog("configInitLogger");
    return 0;
  }

  if (isEnabled("carbonio-logger")) {
    setLdapGlobalConfig("zimbraLogHostname", $config{HOSTNAME});
    setLocalConfig ("smtp_source", $config{SMTPSOURCE});
    setLocalConfig ("smtp_destination", $config{SMTPDEST});
  }
  configLog("configInitLogger");
}

sub configInitCore {

  if ($configStatus{configInitCore} eq "CONFIGURED") {
    configLog("configInitCore");
    return 0;
  }
  configLog("configInitCore");
}

sub configInitMta {

  if ($configStatus{configInitMta} eq "CONFIGURED") {
    configLog("configInitMta");
    return 0;
  }

  if (isEnabled("carbonio-mta")) {
    progress ( "Initializing mta config..." );

    setLocalConfig("postfix_mail_owner", $config{postfix_mail_owner});
    setLocalConfig("postfix_setgid_group", $config{postfix_setgid_group});

    runAsZextras ("/opt/zextras/libexec/zmmtainit $config{LDAPHOST} $config{LDAPPORT}");
    progress ( "done.\n" );
    if (isZCS()) {
      push(@installedServiceList, ('zimbraServiceInstalled', 'amavis'));
      push(@installedServiceList, ('zimbraServiceInstalled', 'antivirus'));
      push(@installedServiceList, ('zimbraServiceInstalled', 'antispam'));
      push(@installedServiceList, ('zimbraServiceInstalled', 'opendkim'));
      push(@enabledServiceList, ('zimbraServiceEnabled', 'amavis'));
      if ($config{RUNAV} eq "yes") {
        push(@enabledServiceList, ('zimbraServiceEnabled', 'antivirus'));
      }
      if ($config{RUNSA} eq "yes") {
        push(@enabledServiceList, ('zimbraServiceEnabled', 'antispam'));
      }
      if ($config{RUNDKIM} eq "yes") {
        push(@enabledServiceList, ('zimbraServiceEnabled', 'opendkim'));
      }
      if ($config{RUNCBPOLICYD} eq "yes") {
        push(@enabledServiceList, ('zimbraServiceEnabled', 'cbpolicyd'));
      }
    }
    setLdapServerConfig("zimbraMtaMyNetworks", $config{zimbraMtaMyNetworks})
      if ($config{zimbraMtaMyNetworks} ne "");


  }
  configLog("configInitMta");
}

sub configInitGALSyncAccts {

  if ($configStatus{configInitGALSyncAccts} eq "CONFIGURED") {
    configLog("configInitGALSyncAccts");
    return 0;
  }

  return 1 unless
    (isEnabled("carbonio-directory-server") && $config{LDAPHOST} eq $config{HOSTNAME});

  #if ($config{ENABLEGALSYNCACCOUNTS} eq "yes") {
    #progress("Creating galsync accounts in all domains...");
    #my $rc = runAsZextras("zmjava com.zimbra.cs.account.ldap.upgrade.LdapUpgrade -b 14531 -v");
    #progress(($rc == 0) ? "done.\n" : "failed.\n");
    #configLog("configInitGALSyncAccts") if ($rc == 0);
  #}
}

sub configCreateDefaultDomainGALSyncAcct {

  if ($configStatus{configCreateDefaultGALSyncAcct} eq "CONFIGURED") {
    configLog("configCreateDefaultGALSyncAcct");
    return 0;
  }

    if (isEnabled("carbonio-appserver")) {
    progress("Creating galsync account for default domain...");
    my $zimbra_server = getLocalConfig ("zimbra_server_hostname");
    my $default_domain = (($newinstall) ? "$config{CREATEDOMAIN}" : "$config{zimbraDefaultDomainName}");
    my $galsyncacct = "galsync." . lc(genRandomPass()) . '@' . $default_domain ;
    my $rc = runAsZextras("/opt/zextras/bin/zmgsautil createAccount -a $galsyncacct -n InternalGAL --domain $default_domain -s $zimbra_server -t zimbra -f _InternalGAL -p 1d");
    progress(($rc == 0) ? "done.\n" : "failed.\n");
    configLog("configCreateDefaultDomainGALSyncAcct") if ($rc == 0);
  }
}

sub configSetEnabledServices {

  if ($configStatus{configSetEnabledServices} eq "CONFIGURED") {
    configLog("configSetEnabledServices");
    return 0;
  }

  foreach my $p (keys %installedPackages) {
    if ($p eq "carbonio-core") {
      push(@installedServiceList, ('zimbraServiceInstalled','stats'));
      next;
    }
    $p =~ s/carbonio-//;
    if ($p eq "appserver") {$p = "mailbox";}
    push(@installedServiceList, ('zimbraServiceInstalled', "$p"));
  }

  foreach my $p (keys %enabledPackages) {
    if ($p eq "carbonio-core") {
      push(@enabledServiceList, ('zimbraServiceEnabled', 'stats'));
      next;
    }
    if ($enabledPackages{$p} eq "Enabled") {
      $p =~ s/carbonio-//;
      if ($p eq "appserver") {
        $p = "mailbox";
        # Add carbonio-appserver webapps to service list
        foreach my $app (@webappList) {
          if ($installedWebapps{$app} eq "Enabled") {
            push(@enabledServiceList, 'zimbraServiceEnabled', "$app");
          }
        }
      }
      push(@enabledServiceList, 'zimbraServiceEnabled', "$p");
    }
  }

  progress ( "Setting services on $config{HOSTNAME}..." );
  setLdapServerConfig($config{HOSTNAME}, @installedServiceList);
  setLdapServerConfig($config{HOSTNAME}, @enabledServiceList);
  progress ( "done.\n" );

  my $rc = runAsZextras("/opt/zextras/libexec/zmiptool >/dev/null 2>/dev/null");

  configLog("configSetEnabledServices");
}

sub failConfig {
  progress ("\n\nERROR\n\n");
  progress ("\n\nConfiguration failed\n\n");
  progress ("Please address the error and re-run carbonio-bootstrap to\n");
  progress ("complete the configuration.\n");
  progress ("\nErrors have been logged to $logfile\n\n");
  exit 1;
}

sub applyConfig {
  defineInstallWebapps();
  saveConfig();
  progress ( "Operations logged to $logfile\n" );

  # On split store node setups, the unused webapps need to be removed before
  # applying any other configuration in order to ensure the installedWebapps
  # variables are properly setup for later steps.
  if (isEnabled("carbonio-appserver")) {
    removeUnusedWebapps();
  }

  configLCValues();

  configInitCore();

  # About SSL
  #
  # On the master ldap server, create a ca and a cert
  # On store and MTA servers, just create a cert.
  #
  # Non-ldap masters use the master CA, which they get from ldap
  # but ldap won't start without a cert.
  #
  # so - ldap - create CA, create cert, init ldap, store CA in ldap
  #
  # non-ldap - fetch CA, create cert

  configCASetup();

  configCreateCert();

  configInstallCert();

  if ($ldapReplica) {
    configCreateServerEntry();
  }

  configSetupLdap();

  if (!$ldapReplica) {
    configCreateServerEntry();
  }

  configSaveCA();

  configSaveCert();

  # Generating dhparam key
  if ($newinstall) {
    progress("Generating dhparam key...");
    my $rc = runAsZextras ("/opt/zextras/common/bin/openssl dhparam -out /opt/zextras/conf/dhparam.pem.crb 2048 > /dev/null 2>&1");
    if( $rc != 0 ){
        progress("\nfailed to generate dhparam key");
        progress("\nCarbonio bootstrap process exited cause one of the subprocess failed.\n");
        exit();
    }else{
        progress ("done.\n");
    }
  }

  # Added the following for bug 103803. Could not just add the cert as a globalConfigValue
  # for zimbraSSldHParam.  See bug 104244.
  setLdapGlobalConfig("zimbraSSLDHParam", "/opt/zextras/conf/dhparam.pem.crb") if $newinstall;

  if (isEnabled("carbonio-appserver")) {

    configSetServicePorts();

    configSetKeyboardShortcutsPref() if (!$newinstall);

    configSetStoreDefaults();
  }

  configLDAPSchemaVersion();

  if (isEnabled("carbonio-directory-server")) {
    configSetTimeZonePref();
    setLdapGlobalConfig("zimbraSkinLogoURL", "https://www.zextras.com")
  }

  if ($newinstall && isInstalled("carbonio-proxy")) {
    configSetProxyPrefs();
  }

  if( (!$newinstall) && isInstalled("carbonio-directory-server") ){
    setProxyBits();
  }

  configInitMta();

  configSetEnabledServices();

  if (isEnabled("carbonio-appserver")) {
    if (isStoreServiceNode()) {
      addServerToHostPool();
    }
    # bug 100730
    if ($config{UIWEBAPPS} eq "no") {
      setLdapServerConfig($config{HOSTNAME}, "zimbraReverseProxyHttpEnabled", "FALSE");
    }
  }

  if (isEnabled("carbonio-mta") && $main::newinstall) {
    my @mtalist = getAllServers("mta");
    if (scalar(@mtalist) gt 1) {
      setLocalConfig("zmtrainsa_cleanup_host", "false")
    } else {
      setLocalConfig("zmtrainsa_cleanup_host", "true")
    }
  }

  configCreateDomain();

  configInitSql();

  configInitLogger();

  configInitGALSyncAccts();

  setupSyslog();

  qx(touch /opt/zextras/.bash_history);
  qx(chown zextras:zextras /opt/zextras/.bash_history);

  if (!$newinstall) {
    startLdap() if ($ldapConfigured);
  }

  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersion', $curVersion);
  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMajor', $curVersionMajor);
  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMinor', $curVersionMinor);
  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionMicro', $curVersionMicroMicro);
  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionType', $curVersionType);
  setLdapServerConfig($config{HOSTNAME}, 'zimbraServerVersionBuild', $curVersionBuild);

  if ($config{STARTSERVERS} eq "yes") {
    if (isEnabled("carbonio-appserver")) {
      qx(chown zextras:zextras /opt/zextras/redolog/redo.log)
        if (($platform =~ m/DEBIAN/ || $platform =~ m/UBUNTU/) && ! $newinstall);
    }
    progress ( "Starting servers..." );
    runAsZextras ("/opt/zextras/bin/zmcontrol stop");
    runAsZextras ("/opt/zextras/bin/zmcontrol start");
    qx($SU "/opt/zextras/bin/zmcontrol status");
    progress ( "done.\n" );

    # Initialize application server specific items
    # only after the application server is running.
    if (isEnabled("carbonio-appserver")) {
      configInstallZimlets();

      progress ( "Restarting mailboxd...");
      runAsZextras("/opt/zextras/bin/zmmailboxdctl restart");
      progress ( "done.\n" );
    }
    if ($newinstall && isStoreServiceNode()) {
      configCreateDefaultDomainGALSyncAcct();
    } else {
      if ($newinstall) {
        progress ("Skipping creation of default domain GAL sync account - not a service node.\n");
      } else {
        progress ( "Skipping creation of default domain GAL sync account - existing install detected.\n" );
      }
    }
  } else {
    progress ( "WARNING: Document and Zimlet initialization skipped because Application Server was not configured to start.\n".
               "WARNING: galsync account creation for default domain skipped because Application Server was not configured to start.\n")
      if (isEnabled("carbonio-appserver"));
  }

  setupCrontab();

  if ($newinstall) {
    runAsZextras ("/opt/zextras/bin/zmsshkeygen");
    runAsZextras ("/opt/zextras/bin/zmupdateauthkeys");
  } else {
    runAsZextras ("/opt/zextras/bin/zmupdateauthkeys");
  }

  configLog ("END");

  print H time(),": CONFIG SESSION COMPLETE\n";

  close H;

  getSystemStatus();

  progress ( "\n\n" );
  chmod 0600, $logfile;
  if (-d "/opt/zextras/log") {
    main::progress("Moving $logfile to /opt/zextras/log\n");
    system("cp -f $logfile /opt/zextras/log/");
    system("chown zextras:zextras /opt/zextras/log/$logFileName");
  } else {
    progress ( "Operations logged to $logfile\n" );
  }
  progress ( "\n\n" );
  if (!defined ($options{c})) {
    ask("Configuration complete - press return to exit", "");
    print "\n\n";
    close LOGFILE;
    exit 0;
  }
}

sub configLog {
  my $stage = shift;
  my $msg = time().": CONFIGURED $stage\n";
  print H $msg;
  #progress ($msg);
}

sub setupSyslog {
  progress ("Setting up syslog.conf...");
  if ( -f "/opt/zextras/libexec/zmsyslogsetup") {
    my $rc = runAsRoot("/opt/zextras/libexec/zmsyslogsetup");
    if ($rc) {
      progress ("Failed\n");
      } else {
      progress ("done.\n");
    }
  } else {
    progress ("Failed\n");
  }
  configLog("setupSyslog");
}

sub setupCrontab {
  progress ("Setting up zextras crontab...");
  detail("crontab: Taking a copy of zextras user crontab file.");
  qx(crontab -u zextras -l > /tmp/crontab.zextras.orig 2> /dev/null);
  detail("crontab: Looking for ZEXTRAS-START in existing crontab entry.");
  my $rc = 0xffff & system("grep ZEXTRAS-START /tmp/crontab.zextras.orig > /dev/null 2>&1");
  if ($rc) {
    detail("crontab: ZEXTRAS-START not found truncating zextras crontab and starting fresh.");
    qx(cp -f /dev/null /tmp/crontab.zextras.orig 2>> $logfile);
  }
  detail("crontab: Looking for ZEXTRAS-END in existing crontab entry.");
  $rc = 0xffff & system("grep ZEXTRAS-END /tmp/crontab.zextras.orig > /dev/null 2>&1");
  if ($rc) {
    detail("crontab: ZEXTRAS-END not found truncating zextras crontab and starting fresh.");
    qx(cp -f /dev/null /tmp/crontab.zextras.orig);
  }
  qx(cat /tmp/crontab.zextras.orig | sed -e '/# ZEXTRAS-START/,/# ZEXTRAS-END/d' > /tmp/crontab.zextras.proc);
  detail("crontab: Adding carbonio-core specific crontab entries");
  qx(cp -f /opt/zextras/conf/crontabs/crontab /tmp/crontab.zextras);

  if (isEnabled("carbonio-directory-server")) {
    detail("crontab: Adding carbonio-directory-server specific crontab entries");
    qx(cat /opt/zextras/conf/crontabs/crontab.ldap >> /tmp/crontab.zextras 2>> $logfile);
  }

  if (isEnabled("carbonio-appserver")) {
    detail("crontab: Adding carbonio-appserver specific crontab entries");
    qx(cat /opt/zextras/conf/crontabs/crontab.store >> /tmp/crontab.zextras 2>> $logfile);
  }

  if (isEnabled("carbonio-logger")) {
    detail("crontab: Adding carbonio-logger specific crontab entries");
    qx(cat /opt/zextras/conf/crontabs/crontab.logger >> /tmp/crontab.zextras 2>> $logfile);
  }

  if (isEnabled("carbonio-mta")) {
    detail("crontab: Adding carbonio-mta specific crontab entries");
    qx(cat /opt/zextras/conf/crontabs/crontab.mta >> /tmp/crontab.zextras 2>> $logfile);
  }

  qx(echo "# ZEXTRAS-END -- DO NOT EDIT ANYTHING BETWEEN THIS LINE AND ZEXTRAS-START" >> /tmp/crontab.zextras);
  qx(cat /tmp/crontab.zextras.proc >> /tmp/crontab.zextras);
  detail("crontab: installing new crontab");
  qx(crontab -u zextras /tmp/crontab.zextras 2> /dev/null);
  progress ("done.\n");
  configLog("setupCrontab");
}

sub getSystemMemory {
  my $os = lc qx(uname -s);
  chomp($os);
  return "unknown" unless $os;
  my $mem;
  if ($os eq "linux") {
    $mem = qx(cat /proc/meminfo | grep ^MemTotal: | awk '{print \$2}');
    chomp($mem);
    $mem = sprintf "%0.1f", $mem/(1024*1024);
  } elsif ($os eq "darwin") {
    $mem = qx(sysctl hw.memsize | awk '{print \$NF}');
    chomp($mem);
    $mem = sprintf "%0.1f", $mem/(1024*1024*1024);
  }
  return $mem;
}

sub mysqlMemoryPercent {
  my $system_mem = shift;
  my $os = lc qx(uname -s);
  chomp($os);
  my $percent = 30;
  return $percent;
}

sub mailboxdMemoryMB {
  my $system_mem = shift;
  my $memory;
  if ($system_mem > 16) {
    $memory = 0.2*$system_mem;
  } else {
    $memory = 0.25*$system_mem;
  }
  return int($memory*1024);
}

sub addServerToHostPool {
  progress ( "Adding $config{HOSTNAME} to MailHostPool in default COS..." );
  my $id = getLdapServerValue("zimbraId", $config{HOSTNAME});
  my $hp = getLdapCOSValue("zimbraMailHostPool");

  if ($id eq "") {
    progress("failed. Couldn't find a server entry for $config{HOSTNAME}\n");
    return undef;
  }
  $hp.=(($hp eq "") ? "$id" : "\n$id");

  my %k;
  my @zmprov_args = ();
  foreach my $serverid (split(/\n/, $hp)) {
    $k{$serverid}=1;
  }
  foreach my $host (keys %k) {
    push(@zmprov_args, ('zimbraMailHostPool', $host));
  }
  my $rc = setLdapCOSConfig('default', @zmprov_args);
  progress(($rc == 0) ? "done.\n" : "failed.\n");
}

sub mainMenu {
  my %mm = ();
  $mm{createsub} = \&createMainMenu;

  displayMenu(\%mm);
}

sub stopLdap {
  main::progress("Stopping ldap...");
  my $rc = runAsZextras("/opt/zextras/bin/ldap stop");
  main::progress(($rc == 0) ? "done.\n" : "failed. ldap had exit status: $rc.\n");
  sleep 5 unless $rc; # give it a chance to shutdown.
  return $rc;
}

sub startLdap {
  main::detail("Checking ldap status....");
  my $rc = runAsZextras("/opt/zextras/bin/ldap status");
  main::detail(($rc == 0) ? "already running.\n" : "not running.\n");

  if ($rc) {
    main::progress("Checking ldap status....");
    $rc = runAsZextras ("/opt/zextras/bin/ldap status");
    main::progress(($rc == 0) ? "already running.\n" : "not running.\n");

    if ($rc) {
      main::progress("Starting ldap...");
      $rc = runAsZextras("/opt/zextras/bin/ldap start");
      main::progress(($rc == 0) ? "done.\n" : "failed with exit code: $rc.\n");
      if ($rc) {
        system("$SU \"/opt/zextras/bin/ldap start 2>&1 | grep failed\"");
        return $rc;
      }
    }
  }
  return 0;
}

sub resumeConfiguration {
  progress ( "\n\nNote\n\n" );
  progress ( "The previous configuration appears to have failed to complete\n\n");
  if (askYN ("Attempt to complete configuration now?", "yes") eq "yes") {
    applyConfig();
  } else {
    %configStatus = ();
  }
}

### end subs


__END__
