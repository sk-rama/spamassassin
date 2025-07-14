package FromNotReturnPath;

use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
	my ($class, $mailsa) = @_;
	$class = ref($class) || $class;
	my $self = $class->SUPER::new($mailsa);
	bless ($self, $class);
	$self->register_eval_rule('check_for_from_not_return_path');

	return $self;
}


# Often spam uses different From: and Return-path:
# while most legitimate e-mails does not.
sub check_for_from_not_return_path {
	my ($self, $msg) = @_;

	my $from = $msg->get('From:addr');
	my $returnPath = $msg->get('Return-path:addr');

	#Mail::SpamAssassin::Plugin::info("FromNotReturnPath: Comparing '$from'/'$returnPath'");

	if ($from ne '' && $returnPath ne '' && $from ne $returnPath) {
		return 1;
	}

	return 0;
}

1;
