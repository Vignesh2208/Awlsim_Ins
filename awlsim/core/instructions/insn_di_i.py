# -*- coding: utf-8 -*-
#
# AWL simulator - instructions
#
# Copyright 2012-2014 Michael Buesch <m@bues.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from __future__ import division, absolute_import, print_function, unicode_literals
from awlsim.common.compat import *

from awlsim.core.instructions.main import * #@nocy
from awlsim.core.operators import *
#from awlsim.core.instructions.main cimport * #@cy


class AwlInsn_DI_I(AwlInsn): #+cdef

	__slots__ = ()

	def __init__(self, cpu, rawInsn):
		AwlInsn.__init__(self, cpu, AwlInsn.TYPE_DI_I, rawInsn)
		self.assertOpCount(0)

	def run(self):
#@cy		cdef S7StatusWord s

		s = self.cpu.statusWord
		accu2, accu1 = self.cpu.accu2.getSignedWord(),\
			       self.cpu.accu1.getSignedWord()
		if self.cpu.is4accu:
			self.cpu.accu2.setDWord(self.cpu.accu3.getDWord())
			self.cpu.accu3.setDWord(self.cpu.accu4.getDWord())
		try:
			quo = abs(accu2) // abs(accu1)
			if int(accu1 < 0) ^ int(accu2 < 0):
				quo = -quo
			mod = abs(accu2) % abs(accu1)
			if accu2 < 0:
				mod = -mod
		except ZeroDivisionError:
			s.A1, s.A0, s.OV, s.OS = 1, 1, 1, 1
			return
		self.cpu.accu1.setDWord(((mod & 0xFFFF) << 16) |\
					(quo & 0xFFFF))
		if quo == 0:
			s.A1, s.A0, s.OV = 0, 0, 0
		elif quo < 0:
			s.A1, s.A0, s.OV = 0, 1, 0
		else:
			s.A1, s.A0, s.OV = 1, 0, 0
		if quo > 0x7FFF:
			s.OV, s.OS = 1, 1
