#!/bin/sh

# Run on VM to bootstrap the Foreman server
# Gary A. Stafford - 01/15/2015
# Modified - 08/19/2015
# Downgrade Puppet on box from 4.x to 3.x for Foreman 1.9 
# http://theforeman.org/manuals/1.9/index.html#3.1.2PuppetCompatibility

# Update system first
sudo yum update -y

if puppet agent --version | grep "3." | grep -v grep 2> /dev/null
then
    echo "Puppet Agent $(puppet agent --version) is already installed. Moving on..."
else
    echo "Puppet Agent $(puppet agent --version) installed. Replacing..."

    sudo rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm && \
    sudo yum -y erase puppet-agent && \
    sudo rm -f /etc/yum.repos.d/puppetlabs-pc1.repo && \
    sudo yum clean all
fi

if ps aux | grep "/usr/share/foreman" | grep -v grep 2> /dev/null
then
    echo "Foreman appears to all already be installed. Exiting..."
else
    sudo yum -y install epel-release http://yum.theforeman.org/releases/1.10/el7/x86_64/foreman-release.rpm && \
    sudo yum -y install foreman-installer nano nmap-ncat vim && \
    sudo foreman-installer --foreman-admin-password demo


    # Set-up firewall
    # https://www.digitalocean.com/community/tutorials/additional-recommended-steps-for-new-centos-7-servers
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --permanent --add-port=69/tcp
    sudo firewall-cmd --permanent --add-port=67-69/udp
    sudo firewall-cmd --permanent --add-port=53/tcp
    sudo firewall-cmd --permanent --add-port=53/udp
    sudo firewall-cmd --permanent --add-port=8443/tcp
    sudo firewall-cmd --permanent --add-port=8140/tcp

    sudo firewall-cmd --reload
    sudo systemctl enable firewalld

    # First run the Puppet agent on the Foreman host which will send the first Puppet report to Foreman,
    # automatically creating the host in Foreman's database
    sudo puppet agent --test --waitforcert=60

    # Optional, install some optional puppet modules on Foreman server to get started...
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-ntp
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-git
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-vcsrepo
    sudo puppet module install -i /etc/puppet/environments/production/modules garethr-docker
    sudo puppet module install -i /etc/puppet/environments/production/modules jfryman-nginx
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-haproxy
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-apache
    sudo puppet module install -i /etc/puppet/environments/production/modules puppetlabs-java
    sudo puppet module install -i /etc/puppet/environments/production/modules duritong-sysctl
fi

echo "Getting OpenSCAP ready..."

# install packages
sudo yum -y install ruby193-rubygem-openscap ruby193-rubygem-foreman_openscap rubygem-smart_proxy_openscap openscap-engine-sce openscap-utils tfm-rubygem-foreman_openscap git

# bug: https://bugzilla.redhat.com/show_bug.cgi?id=1225993
curl https://github.com/theforeman/smart_proxy_openscap/commit/f13224b5711dfa0959872933f21fe3bfec6e260e.patch > /tmp/smart_proxy_openscap_1225993.patch
cd /usr/share/gems/gems/smart_proxy_openscap-0.4.1/ && patch -p1 < /tmp/smart_proxy_openscap_1225993.patch

# https://groups.google.com/forum/#!topic/foreman-users/cTAZOYDhq5A
cat <<. >>/etc/foreman/settings.yaml

:trusted_puppetmaster_hosts: $(hostname)

.

# restart foreman and foreman-proxy
for s in foreman-proxy httpd ; do
    for k in stopped running ; do
        puppet resource service $s ensure=$k
    done
done

# install scap and cis puppet modules from github
sudo git clone https://github.com/arildjensen/cis-puppet /etc/puppet/environments/production/modules/cis
cd /etc/puppet/environments/production/modules && patch -p1 < /vagrant/cis.patch

sudo git clone https://github.com/theforeman/puppet-foreman_scap_client /etc/puppet/environments/production/modules/foreman_scap_client

# link my homebrew module
cd /etc/puppet/environments/production/modules && ln -s /vagrant/osd_secure

cat <<. >/etc/profile.d/pretend-redhat.sh
export FACTER_operatingsystem=RedHat
.

# we'll need it to run smart-proxy-openscap-send manually
mkdir /root/logs

# install gui
sudo yum -y install scap-workbench xorg-x11-xauth dejavu-lgc-sans-fonts

