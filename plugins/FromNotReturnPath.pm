package FromNotReturnPath;
1;

use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
        my ($class, $mailsa) = @_;
        $class = ref($class) || $class;
        my $self = $class->SUPER::new( $mailsa );
        bless ($self, $class);
        $self->register_eval_rule ( 'check_for_from_not_return_path' );
        
        return $self;
}


# Often spam uses different From: and Return-Path:
# while most legitimate e-mails does not.
sub check_for_from_not_return_path {
        my ($self, $msg) = @_;

        my $from = lc $msg->get( 'From:addr' );
        my $returnpath = lc $msg->get( 'Return-Path:addr' );

        #Mail::SpamAssassin::Plugin::dbg( "FromNotReturnPath: Comparing '$from'/'$returnpath" );

        if ( $from ne '' && $returnpath ne '' && $from ne $returnpath ) {
                return 1;
        }

        return 0;
}
