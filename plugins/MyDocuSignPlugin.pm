package Mail::SpamAssassin::Plugin::MyDocuSignPlugin;
0;


###
# You must install Email::Address;
# Linux:
# cpan
# cpan[1]> install Email::Address
### 

use strict;
use Email::Address;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Logger;
our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_MyDocuSignPlugin"); # type does not matter

  return $self;
}


# my function to get two-level domain from fqdn
sub get_domain {
    my %params = @_;

    my $fqdn = $params{fqdn};

    my $dot_count = () = $fqdn =~ /\./g;

    if ($dot_count < 2) {
    # it is not three-level TLD
        return $fqdn;
    }
    else {
        my @parts = split(/\./, $fqdn);
        my $dn1 = pop(@parts);
        my $dn2 = pop(@parts);
        return $dn2 . "." . $dn1;
    }
}

# Often spam uses To: another from your local domains e.g. To: news@newletters.com
# while most legitimate e-mails does not.
sub check_MyDocuSignPlugin {

    dbg("MyDocuSignPlugin is ready to use");

    my ($self, $msg) = @_;

    my $tag_name = "DOCUSIGNTAG";
    my @docusing_domains = ("docusign.net", "docusign.com");

    # my $to = lc $msg->get( 'To:addr' );
    # my $returnpath = lc $msg->get( 'Return-Path:addr' );

    # 'ToCc' can be used to mean the contents of both the 'To' and 'Cc' headers.
    my $from_temp_name = lc $msg->get( 'From:name' );
    my $from_temp_email = lc $msg->get( 'From:addr' );
    dbg("MyDocuSignPlugin: From mail address name is: $from_temp_name\n");
    dbg("MyDocuSignPlugin: From mail email is: $from_temp_email\n");

    if ( $from_temp_name =~ /DocuSign|DocuSing|Docu Sign|Docu Sing/i ) {
        dbg("MyDocuSignPlugin: detect DocuSign email, From header contain name: $from_temp_name and email addres: $from_temp_email\n");

        my @addresses = Email::Address->parse($from_temp_email);
        my @from_domains;
        my @from_emails;

        for my $email (@addresses) {
            my $email_address = $email->address;
            my $domain_part = $email->host;
            $domain_part = get_domain(fqdn => $domain_part);
            push @from_emails, $email_address;
            push @from_domains, $domain_part;
        }
        dbg("MyDocuSignPlugin: detect DocuSign email, From header contains this emails: @from_emails\n");
        dbg("MyDocuSignPlugin: detect DocuSign email, From header contains this emails domains: @from_domains\n");


        # inicialize $find_status and $find_domain variables
        # $find_status will be exit code for this script, inicialize to 1: When script return 1, than spamassassin take action and assign score to this rule
        my $find_status = 1; 
        my $find_domain = "";

        # loop for every domains in @from_domains array
        # check if actual item in loop is in our defined @docusing_domains array
        # if yes, change $find_status variables to 1 (True) and save such actual domain to $find_domain variable 
        for my $domain (@from_domains){
            if ( grep( /^$domain$/, @docusing_domains ) ) {
                dbg("MyDocuSignPlugin: $domain is in docusing_domains array @docusing_domains");
                $find_status = 0;     # we find a allowed domain, $find_status is exit code for this script, so exit code for script will be zero, spamassassin take no action    
                $find_domain = $domain;
            }
            else {
                dbg("MyDocuSignPlugin:: $domain is not in our docusing_domains array \(@docusing_domains\)");
            }
        }
        if ($find_status == 1) {
            dbg("MyDocuSignPlugin: Detect Fake DocuSign email. Set up it as spam. From header email address: $from_temp_email\n");
            $msg->set_tag("$tag_name", "FAKE DocuSign email");
            return $find_status;
        }
        else {
            dbg("MyDocuSignPlugin: Detect Original DocuSign email. Set up it as not spam. From header email address: $from_temp_email\n");
            $msg->set_tag("$tag_name", "Original DocuSign email");
            return $find_status;
        }
    }
    else {
        dbg("MyDocuSignPlugin: It is not DocuSign email, From header contain name: $from_temp_name and email address $from_temp_email\n");
        $msg->set_tag("$tag_name", "NOT DocuSign email");
        return 0;
    }

    return 0;
}
