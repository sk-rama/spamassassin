package Mail::SpamAssassin::Plugin::MyLocalPlugin;
0;

use strict;
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
  $self->register_eval_rule("check_MyLocalPlugin"); # type does not matter

  return $self;
}

# Often spam uses To: another from your local domains e.g. To: news@newletters.com
# while most legitimate e-mails does not.
sub check_MyLocalPlugin {

        dbg("MyLocalPlugin is ready to use");

        my ($self, $msg) = @_;
        my $pms = $msg->{permsgstatus};

        my $tag_name = "LOCAL_HEADER_TO";
        my @my_domains = ("secar.cz", "sherlog.cz", "sherlog.com", "sherlog.eu", "sherlog.sk", "pipelines.cz", "sherlogvision.cz", "czechtraffic.cz", "sherlogtrace.cz", "secarstar.cl", "importtankovani.cz");

        # my $to = lc $msg->get( 'To:addr' );
        # my $returnpath = lc $msg->get( 'Return-Path:addr' );

        # 'ToCc' can be used to mean the contents of both the 'To' and 'Cc' headers.
        my $to_temp = lc $msg->get( 'ToCc' );
        dbg("MyLocalPlugin: To mail addresses from to variable is: $to_temp\n");

        # May return multiple emails as string: e.g: <user1@example.com>, <user2@example.com>, <user3@test.com>
        # or if there only one email in 'To' header, return string "user@example.com"  
        # if there is more that one email, remove from such string chars "<", ">", "," 
        $to_temp =~ s/[<>,]+//g;

        # create array @to_temp from string from all emails in string $to_temp
        my @to_temp = split(/\s+/, $to_temp);

        # debug information
        dbg("MyLocalPlugin: To mail addresses from to_temp variable is: $to_temp\n");
 
        # If mail header To: is missing, return as true
        if ($to_temp eq "") {
            dbg("MyLocalPlugin: mail header To and Cc is not defined");
            #$pms->set_tag("ABCDEF952", "not defined");
            return 1;
        }       
        else {
            # create empty array @to_cc_domains
            # loop for every email in @to_temp array, split every email to user and domain part
            # domain part add to @to_cc_domains array
            my @to_cc_domains;
            for my $email (@to_temp){
                dbg("MyLocalPlugin email that I find: $email\n");
                my @to_split = split(/@/, $email);
                my $email_user = $to_split[0];
                my $email_domain = $to_split[1];
                push @to_cc_domains, $email_domain;
            }
            dbg("MyLocalPlugin: destinations domain from emails are: @to_cc_domains");

            # inicialize $find_status and $find_domain variables
            # $find_status will be exit code for this script, inicialize to 1: When script return 1, than spamassassin take action and assign score to this rule
            my $find_status = 1; 
            my $find_domain = "";
   
            # loop for every domains in @to_cc_domains array
            # check if actual item in loop is in our defined @my_domains array
            # if yes, change $find_status variables to 1 (True) and save such actual domain to $find_domain variable 
            for my $domain (@to_cc_domains){
                if ( grep( /^$domain$/, @my_domains ) ) {
                    dbg("MyLocalPlugin: $domain is in our domain array @my_domains");
                    $find_status = 0;     # we find a allowed domain, $find_status is exit code for this script, so exit code for script will be zero, spamassassin take no action    
                    $find_domain = $domain;
                }
                else {
                    dbg("MyLocalPlugin: $domain is not in our domain array @my_domains");
                }
            }
            dbg("MyLocalPlugin: Can I find any allowed domain in To or Cc header? Answer is $find_status: zero means True, one means False");
            dbg("MyLocalPlugin: Last domain I can find in allowed domains is: $find_domain");
            return $find_status;
        }
}
