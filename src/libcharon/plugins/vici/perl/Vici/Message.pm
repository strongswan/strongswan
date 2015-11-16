package Vici::Message;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(new, from_data, hash, encode, raw);
our @VERSION = 0.9;

use strict;
use Switch;
use Vici::Transport;

use constant {
    SECTION_START => 1,   # Begin a new section having a name
    SECTION_END   => 2,   # End a previously started section
    KEY_VALUE     => 3,   # Define a value for a named key in the section
    LIST_START    => 4,   # Begin a named list for list items
    LIST_ITEM     => 5,   # Define an unnamed item value in the current list
    LIST_END      => 6,   # End a previously started list
};

sub new {
    my $class = shift;
    my $hash = shift;
    my $self = {
        Hash => $hash
    };
    bless($self, $class);
    return $self;
}

sub from_data {
    my $class = shift;
    my $data = shift;
    my %hash = ();

    parse($data, \%hash);

    my $self = {
        Hash => \%hash
    };
    bless($self, $class);
    return $self;
}

sub hash {
    my $self = shift;
    return $self->{Hash};
}

sub encode {
    my $self = shift;
    return encode_hash($self->{'Hash'});
}

sub raw {
    my $self = shift;
    return '{' . raw_hash($self->{'Hash'}) . '}';
}

# private functions

sub parse {
    my $data = shift;
    my $hash = shift;

    while (length($data) > 0)
    {
        (my $type, $data) = unpack('Ca*', $data);

		if ($type == SECTION_END)
		{
			return $data;
		}

        (my $key, $data) = unpack('C/a*a*', $data);

        switch ($type)
        {       
            case KEY_VALUE
            {
                (my $value, $data) = unpack('n/a*a*', $data);
                $hash->{$key} = $value;
            }
            case SECTION_START
            {
                my %section = ();
                $data = parse($data, \%section);
                $hash->{$key} = \%section;
            }
            case LIST_START
            {
                my @list = ();
                my $more = 1;

                while (length($data) > 0 and $more)
                {
                    (my $type, $data) = unpack('Ca*', $data);
                    switch ($type)
                    {
                        case LIST_ITEM
                        {
                            (my $value, $data) = unpack('n/a*a*', $data);
                            push(@list, $value);
                        }
                        case LIST_END
                        {
                            $more = 0;
                            $hash->{$key} = \@list;
                         }
                        else
                        {
                            die "message parsing error: ", $type, "\n"
                        }
                    }
                }
            }
            else
            {
                die "message parsing error: ", $type, "\n"
            }
        } 
	}
    return $data;
}


sub encode_hash {
    my $hash = shift;
    my $enc = '';

    while ( (my $key, my $value) = each %$hash )
    {
        switch (ref($value))
        {
            case 'HASH'
            {
                $enc .= pack('CC/a*', SECTION_START, $key);
                $enc .= encode_hash($value);
                $enc .= pack('C', SECTION_END);
            }
            case 'ARRAY'
            {
                $enc .= pack('CC/a*', LIST_START, $key);

                foreach my $item (@$value)
                {
                    $enc .= pack('Cn/a*', LIST_ITEM, $item);
                }
                $enc .= pack('C', LIST_END);
            }
            else
            {
                $enc .= pack('CC/a*n/a*', KEY_VALUE, $key, $value);
            }
        }
    }
    return $enc;        
}

sub raw_hash {
    my $hash = shift;
    my $raw = '';
    my $first = 1;

    while ( (my $key, my $value) = each %$hash )
    {
        if ($first)
        {
            $first = 0;
        }
        else
        {
            $raw .= ' ';
        }
        $raw .= $key;

        switch (ref($value))
        {
            case 'HASH'
            {
                $raw .= '{' . raw_hash($value) . '}';
            }
            case 'ARRAY'
            {
                my $first_item = 1;
                $raw .= '[';

                foreach my $item (@$value)
                {
                    if ($first_item)
                    {
                        $first_item = 0;
                    }
                    else
                    {
                        $raw .= ' ';
                    }
                    $raw .= $item;
                }
                $raw .= ']';
            }
            else
            {
                $raw .= '=' . $value;
            }
        }
    }
    return $raw;        
}

1;


