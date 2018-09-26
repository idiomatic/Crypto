# Player ID

The player-character identity can be announced in an add-on channel
and verified via a published public key.  A signed message that
originated from the public player may be broadcasted on that channel.
That message may be repeated upon request of an uninformed player with
respondents choosing to
[unicast](https://en.wikipedia.org/wiki/Unicast), broadcast, or ignore
to avoid [amplification
attacks](https://en.wikipedia.org/wiki/Denial-of-service_attack#Amplification).

To avoid spreading misinformation after a character rename or
deletion, the stashed identification message should eventually expire,
and be superseded by the most recent valid message, regardless of the
sender.  It is up to the public player to defend their character name
until the expiration.

# Tipping

## Recommended UI/UX

It is recommended that a non-invasive player-centric-designed UI be
present, otherwise the add-on risks becoming spurned &mdash; and other
more player-respectful add-ons also with tipping become tainted.

* include a modest button in the add-on's main frame's lower-right
  corner, about box, or settings panel.
* pressing the button presents an easily dismissible pledge panel to
  specify a pledge amount.
* the panel may inoffensively disregard comically minuscule amounts
  (*e.g.*, less than 1 silver).
* the pledge panel may reveal whether the recipient is known on this
  realm, and the age of the most recent valid identity announcement;
  this would be a suitable time to request the identity if not already
  known nor overheard.
* upon character arrival to a mailbox with an outstanding pledge less
  than their gold-on-hand, the add-on sends mail with tip attached to
  the recipient (minus postage).
* the mailbox panel should not have its behavior overtly changed; it
  should discretely send the tip rather than linger in the message
  composition panel.
* mail with an attached tip may trigger the mailbox panel to confirm
  sending an amount; this behavior should be left as-is.
* the player may be notified in the default chat frame that the tip
  was sent, as to explain why the "coin drop" sound just played.
* the player may be notified in the default chat frame that there are
  insufficent funds at this time; this message may be omitted on
  subsequent mailbox visits.
* the insufficient funds default chat frame message may include
  instructions how to revise or cancel the pledge.
* once the tip is believed sent, the add-on should reset the pledge to
  zero; preference should lean to resetting versus sending duplicates.
