# An example how to create a valid hash on the Stream calling side (e.g. cgi)

use Digest::MD5;

# This could be the URL:
# rtmp://edge4.someserver.com/events/171426.f35d2bc39ee9409a02a29dbba19688f6/protected/axel/mofacam.rm?rn.workflow=axel&amp;rn.method=protected&amp;rn.region=HH_DE&amp;rn.cluster=REALMEDIA3"><span class="s1">rtsp://rvedge4.euro.real.com/events/171426.f35d2bc39ee9409a02a29dbba19688f6/protected/axel/cool_video?info.workflow=axel&amp;info.method=protected

$secret	= 'moo to you';

$filepath = 'protected/axel/EA';
$query_string = '?rn.workflow=axel&amp;info.method=protected';

(undef, $min, $hour, $mday, $mon, $year) = gmtime(time());

$current_date = sprintf ("%02d%02d%02d%02d%02d", $year - 100, $mon + 1, $mday, $hour, $min) ;
$current_date_short = sprintf ("%02d%02d%02d", $mday, $hour, $min) ;

print "\n\ntoken: $secret$current_date$filepath$query_string \n";

print "token: " . sprintf ("%s.%s", $current_date_short, Digest::MD5->new->add($secret . $current_date . $filepath . $query_string)->hexdigest) . "\n\n";
