/*
 * return IPsec copyright notice
 * Copyright (C) 2001, 2002  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: copyright.c,v 1.6 2005/11/02 21:51:13 as Exp $
 */
#include "internal.h"
#include "freeswan.h"

static const char *co[] = {
 "Copyright (C) 1999-2007  Henry Spencer, Richard Guy Briggs,",
 "    D. Hugh Redelmeier, Sandy Harris, Claudia Schmeing,",
 "    Michael Richardson, Angelos D. Keromytis, John Ioannidis,",
 "",
 "    Ken Bantoft, Stephen J. Bevan, JuanJo Ciarlante, Mathieu Lafon,",
 "    Stephane Laroche, Kai Martius, Stephan Scholz, Tuomo Soini, Herbert Xu,",
 "",
 "    Andreas Steffen, Martin Berner, Marco Bertossa, David Buechi,",
 "    Ueli Galizzi, Christoph Gysin, Andreas Hess, Patric Lichtsteiner,",
 "    Michael Meier, Andreas Schleiss, Ariane Seiler,",
 "    Mario Strasser, Lukas Suter, Roger Wegmann, Simon Zwahlen,",
 "    Zuercher Hochschule Winterthur (Switzerland).",
 "",
 "    Tobias Brunner, Fabian Hartmann, Noah Heusser, Jan Hutter,",
 "    Daniel Roethlisberger, Martin Willi, Daniel Wydler, Andreas Steffen,",
 "    Hochschule fuer Technik Rapperswil (Switzerland).",
 "",
 "This program is free software; you can redistribute it and/or modify it",
 "under the terms of the GNU General Public License as published by the",
 "Free Software Foundation; either version 2 of the License, or (at your",
 "option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.",
 "",
 "This program is distributed in the hope that it will be useful, but",
 "WITHOUT ANY WARRANTY; without even the implied warranty of",
 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General",
 "Public License (file COPYING in the distribution) for more details.",
 NULL
};

/*
 - ipsec_copyright_notice - return copyright notice, as a vector of strings
 */
const char **
ipsec_copyright_notice()
{
	return co;
}
