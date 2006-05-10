/** @mainpage

@section design strongSwans overall design

IKEv1 and IKEv2 is handled in different keying daemons. The ole IKEv1 stuff is
completely handled in pluto, as it was all the times. IKEv2 is handled in the
new keying daemon, which is called #charon. 
Daemon control is done over unix sockets. Pluto uses whack, as it did for years.
Charon uses another socket interface, called stroke. Stroke uses another
format as whack and therefore is not compatible to whack. The starter utility,
wich does fast configuration parsing, speaks both the protocols, whack and
stroke. It also handles daemon startup and termination. 
Pluto uses starter for some commands, for other it uses the whack utility. To be
as close to pluto as possible, charon has the same split up of commands to
starter and stroke. All commands are wrapped together in the ipsec script, which
allows transparent control of both daemons.
@verbatim

         +-----------------------------------------+
         |                  ipsec                  |
         +-----+--------------+---------------+----+
               |              |               |
               |              |               |
               |        +-----+-----+         |
         +-----+----+   |           |   +-----+----+
         |          |   |  starter  |   |          |
         |  stroke  |   |           |   |   whack  |
         |          |   +---+--+----+   |          |
         +------+---+       |  |        +--+-------+
                |           |  |           |
            +---+------+    |  |    +------+--+
            |          |    |  |    |         |
            |  charon  +----+  +----+  pluto  |
            |          |            |         |
            +-----+----+            +----+----+
                  |                      |
            +-----+----+                 |
            |    LSF   |                 |
            +-----+----+                 |
                  |                      |
            +-----+----+            +----+----+
            | RAW Sock |            | UDP/500 |
            +----------+            +---------+

@endverbatim
Since IKEv2 uses the same port as IKEv1, both daemons must listen to UDP port
500. Under Linux, there is no clean way to set up two sockets at the same port.
To reslove this problem, charon uses a RAW socket, as they are used in network
sniffers. An installed Linux Socket Filter (LSF) filters out all none-IKEv2
traffic. Pluto receives any IKE message, independant of charons behavior.
Therefore plutos behavior is changed to discard any IKEv2 traffic silently.

To gain some reusability of the code, generic crypto and utility functions are 
separeted in a shared library, libstrongswan.

*/