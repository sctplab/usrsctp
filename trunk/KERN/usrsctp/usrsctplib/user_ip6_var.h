/* __Userspace__ version of ip6_var.h */

#define IN6_IFF_ANYCAST		0x01	/* anycast address */
#define IN6_IFF_TENTATIVE	0x02	/* tentative address */
#define IN6_IFF_DUPLICATED	0x04	/* DAD detected duplicate */
#define IN6_IFF_DETACHED	0x08	/* may be detached from the link */
#define IN6_IFF_DEPRECATED	0x10	/* deprecated address */
#define IN6_IFF_NODAD		0x20	/* don't perform DAD on this address
					 * (used only at first SIOC* call)
					 */
#define IN6_IFF_AUTOCONF	0x40	/* autoconfigurable address. */
#define IN6_IFF_TEMPORARY	0x80	/* temporary (anonymous) address. */
#define IN6_IFF_NOPFX		0x8000	/* skip kernel prefix management.
					 * XXX: this should be temporary.
					 */

/* do not input/output */
#define IN6_IFF_NOTREADY (IN6_IFF_TENTATIVE|IN6_IFF_DUPLICATED)
