#!/usr/bin/python
#
# Copyright 2016 University of Twente. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Comware 5 generator."""

__author__ = 't.a.hoogendijk@utwente.nl (Tjeerd Hoogendijk)'
__author__ = 'l.m.c.haverkotte@utwente.nl (Leon Haverkotte)'


import datetime
import logging
import re

from third_party import ipaddr
import aclgenerator
import nacaddr

_ACTION_TABLE = {
    'accept': 'rule permit',
    'deny': 'rule deny',
    'reject': 'rule deny',
    'next': '! next',
    'reject-with-tcp-rst': 'rule deny', # tcp rst not supported
}

# generic error class
class Error(Exception):
  """Generic error class."""
  pass

class UnsupportedComwareAccessListError(Error):
  """Raised when we're give a non numbered acl list."""
  pass

class BasicAclTermError(Error):
  """Raised when there is a problem in a basic access list."""
  pass

class ExtendedAclTermError(Error):
  """Raised when there is a problem in a extended access list."""
  pass

class TermBasic(object):
  """A single basic ACL Term."""

  def __init__(self, term, filter_name, af=4):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    self.logstring = ''
    self.af = af

    # sanity checking for basic acls
    if self.term.protocol:
      raise BasicAclTermError(
          'Basic ACLs cannot specify protocols')
    if self.term.icmp_type:
      raise BasicAclTermError(
          'ICMP Type specifications are not permissible in basic ACLs')
    if (self.term.source_address
        or self.term.source_address_exclude
        or self.term.destination_address
        or self.term.destination_address_exclude):
      raise BasicAclTermError(
          'Basic ACLs cannot use source or destination addresses')
    if self.term.option:
      raise BasicAclTermError(
          'Basic ACLs prohibit use of options')
    if self.term.source_port or self.term.destination_port:
      raise BasicAclTermError(
          'Basic ACLs prohibit use of port numbers')
    if self.term.logging:
      self.logstring = ' logging'
   
  def __str__(self):
    
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'comware' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'comware' in self.term.platform_exclude:
        return ''
    ret_str = []

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == 'comware':
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      if self.af == 6:
        protocol = ['ipv6']
      else:
        protocol = ['ip']
    else:
      # pylint: disable-msg=C6402
      protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)
      # pylint: disable-msg=C6402    
    
    
    logging.debug ('Comware af type = %d', self.af) 
    if self.af == 4:
      v4_addresses = [x for x in self.term.address if type(x) != nacaddr.IPv6]
      if self.filter_name:
          ret_str.append('rule remark %s' % (self.term.name))
          comment_max_width = 62
          comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
          if comments and comments[0]:
            for comment in comments:
              ret_str.append('rule remark %s' % (comment))

          action = _ACTION_TABLE.get(str(self.term.action[0]))
          if v4_addresses:
            for addr in v4_addresses:
              if addr.prefixlen == 32:
                ret_str.append(' %s source %s' % (action, addr.ip))
              else:
                ret_str.append(' %s source %s %s' % (action, addr.network, addr.hostmask)) 
            ret_str.append(' %s source %s%s' % (action,'any', self.logstring))

      else:
          ret_str.append('rule remark ' + self.term.name)
          comment_max_width = 62
          comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
          if comments and comments[0]:
            for comment in comments:
              ret_str.append('rule remark ' + str(comment))

          action = _ACTION_TABLE.get(str(self.term.action[0]))
          if v4_addresses:
            for addr in v4_addresses:
              if addr.prefixlen == 32:
                ret_str.append(' %s source %s' % (action, addr.ip))
              else:
                ret_str.append(' %s source %s %s' % (action, addr.network,
                                                addr.hostmask))
          else:
            ret_str.append(' %s %s' % (action, 'source any'))
  
    if self.af == 6:
      v6_addresses = [x for x in self.term.address if type(x) == nacaddr.IPv6]
      if self.filter_name:
          ret_str.append('rule remark %s' % (self.term.name))
          comment_max_width = 62
          comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
          if comments and comments[0]:
            for comment in comments:
              ret_str.append('rule remark %s ' % (comment))

          action = _ACTION_TABLE.get(str(self.term.action[0]))
          if v6_addresses:
            for addr in v6_addresses:
              if addr.prefixlen == 32:
                ret_str.append(' %s source %s' % (action, addr.ip))
              else:
                ret_str.append(' %s source %s' % (action, addr.with_prefixlen))
          else:
            ret_str.append(' %s source %s%s' % (action,'any', self.logstring))

      else:
          ret_str.append('rule remark ' + self.term.name)
          comment_max_width = 63
          comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
          if comments and comments[0]:
            for comment in comments:
              ret_str.append('rule remark ' + str(comment))

          action = _ACTION_TABLE.get(str(self.term.action[0]))
          if v6_addresses:
            for addr in v6_addresses:
              if addr.prefixlen == 128:
                ret_str.append(' %s source %s' % (action, addr.ip))
              else:
                ret_str.append(' %s source %s' % (action, addr.with_prefixlen))
          else:
            ret_str.append(' %s %s' % (action, 'source any'))

    return '\n'.join(ret_str)


class Term(aclgenerator.Term):
  """A single ACL Term."""
  
  def __init__(self, term, af=4):
    self.term = term
    self.options = []
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.

    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    ret_str = ['\n']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      ret_str.append('rule remark Term %s' % self.term.name)
      ret_str.append('rule remark not rendered due to protocol/AF mismatch.')
      return '\n'.join(ret_str)

    ret_str.append('rule remark ' + self.term.name)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('rule remark ' + str(line)[:100])

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == 'comware':
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      if self.af == 6:
        protocol = ['ipv6']
      else:
        protocol = ['ip']
    else:
      # pylint: disable-msg=C6402
      protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)
      # pylint: disable-msg=C6402

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', self.af)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.af)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
    else:
      # source address not set
      source_address = ['source any']

    # destination address
    if self.term.destination_address:
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', self.af)
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', self.af)
      if destination_address_exclude:
        destination_address = nacaddr.ExcludeAddrs(
            destination_address,
            destination_address_exclude)
    else:
      # destination address not set
      destination_address = ['destination any']

    # options
    opts = [str(x) for x in self.term.option]
    if self.PROTO_MAP['tcp'] in protocol and ('tcp-established' in opts or
                                              'established' in opts):
      self.options.extend(['established'])

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    if self.term.logging:
      self.options.append(' logging')

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.af)

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              for icmp_type in icmp_types:
                ret_str.extend(self._TermletToStr(
                    _ACTION_TABLE.get(str(self.term.action[0])),
                    proto,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    icmp_type,
                    self.options))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport,
                    icmp_type, option):
    """Take the various compenents and turn them into a comware acl line.

    Args:
      action: str, action
      proto: str, protocl
      saddr: str or ipaddr, source address
      sport: str list or none, the source port
      daddr: str or ipaddr, the destination address
      dport: str list or none, the destination port
      icmp_type: icmp-type numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the comware acl line, suitable for printing.

    Raises:
      UnsupportedComwareAccessListError: When unknown icmp-types specified
    """
    # inet
    if type(saddr) is nacaddr.IPv4 or type(saddr) is ipaddr.IPv4Network:
         saddr = 'source %s %s' % (saddr.ip, saddr.hostmask)
    if type(daddr) is nacaddr.IPv4 or type(daddr) is ipaddr.IPv4Network:
        daddr = 'destination %s %s' % (daddr.ip, daddr.hostmask)

    # inet6
    if type(saddr) is nacaddr.IPv6 or type(saddr) is ipaddr.IPv6Network:
        saddr = 'source %s' % (saddr.with_prefixlen)
    if type(daddr) is nacaddr.IPv6 or type(daddr) is ipaddr.IPv6Network:
        daddr = 'destination %s' % (daddr.with_prefixlen)


    # fix ports
    if not sport:
      sport = ''
    elif sport[0] != sport[1]:
      sport = 'source-port range %d %d' % (sport[0], sport[1])
    else:
      sport = 'source-port eq %d' % (sport[0])

    if not dport:
      dport = ''
    elif dport[0] != dport[1]:
      dport = 'destination-port range %d %d' % (dport[0], dport[1])
    else:
      dport = 'destination-port eq %d' % (dport[0])

    if not option:
      option = ['']

    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if proto == self.PROTO_MAP['udp'] and 'established' in sane_options:
      sane_options.remove('established')

    ret_lines = []

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    
    
    icmp_type = str(icmp_type)   

    if icmp_type:
      icmp_type = 'icmp-type ' + icmp_type
      ret_lines.append(' %s %s %s %s %s %s %s %s' % (action, proto, saddr,
                                                     sport, daddr, dport,
                                                     icmp_type,
                                                     ' '.join(sane_options)
                                                    ))
    else:
      ret_lines.append(' %s %s %s %s %s %s %s' % (action, proto, saddr,
                                                  sport, daddr, dport,
                                                  ' '.join(sane_options)
                                                 ))

    # remove any trailing spaces and replace multiple spaces with singles
    stripped_ret_lines = [re.sub('\s+', ' ', x).rstrip() for x in ret_lines]
    return stripped_ret_lines


class Comware5(aclgenerator.ACLGenerator):
  """A comware policy object."""

  _PLATFORM = 'comware5'
  _DEFAULT_PROTOCOL = 'ip'
  _SUFFIX = '.cmw5'
  # Protocols should be emitted as numbers.
  _PROTO_INT = True

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['address',
                                      'counter',
                                      'expiration',
                                      'logging',
                                      'policer',
                                      'port',
                                      'qos',
                                     ])

  def _TranslatePolicy(self, pol, exp_info):
    self.comware_policies = []
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    good_filters = ['inet', 'inet6', 'mixed'] 
    new_terms = []

    logging.debug ('Comware has %d filters' , len(pol.filters))

    for header, terms in pol.filters:
      if not self._PLATFORM in header.platforms:
        continue

      filter_options = header.FilterOptions('comware5')
      filter_name = header.FilterName(self._PLATFORM)
      #extract filter type from header
      filter_type = 'inet'

      if (len(filter_options) < 2):
                 raise UnsupportedComwareAccessListError(
                'acl name without acl number not supported by comware \n') 
      if (int(filter_options[1]) not in range(2000, 3999)):
        raise UnsupportedComwareAccessListError(
              'acl name without acl number not supported by comware good types: \n' +  
              ' INTEGER<2000-2999> Specify a basic acl \n' +
              ' INTEGER<3000-3999> Specify an advanced acl \n' +
              ' INTEGER<4000-4999> Specify an ethernet frame header acl (not supported by capirca)') 
      else:
           acl_number = int(filter_options[1])
      
      if len(filter_options) > 2:
        filter_type = filter_options[2]

      # check if filter type is renderable
      if filter_type not in good_filters:
        raise UnsupportedComwareAccessListError(
            'access list type %s not supported by %s (good types: %s)' % (
                filter_type, self._PLATFORM, str(good_filters)))

      filter_list = [filter_type]
      if filter_type == 'mixed':
        #(loop through and generate output for inet then inet6 in sequence)
        filter_list = ['inet', 'inet6']

      
      for next_filter in filter_list:
        logging.debug ('%s for %s has %d terms ', filter_name, self._PLATFORM,  len(terms))
        new_terms = []
        for term in terms:
            #print 'next_filter is %s', next_filter
            af = 'inet'

            if next_filter == 'inet6':
              af = 'inet6'
            term = self.FixHighPorts(term, af=af)
            if not term:
              continue

            if term.expiration:
              if term.expiration <= exp_info_date:
                logging.info('INFO: Term %s in policy %s expires '
                             'in less than two weeks.', term.name, filter_name)
              if term.expiration <= current_date:
                logging.warn('WARNING: Term %s in policy %s is expired and will '
                             'not be rendered.', term.name, filter_name)
                continue

            # render terms based on filter type
            # if (2000 <= acl_number <= 2999):
            #     #  keep track of sequence numbers across terms
            #     new_terms.append(TermBasic(term, filter_name))
            # elif 3000 <= acl_number <= 3999:
            #   if af == 'inet':
            #     new_terms.append(Term(term, 4))
            #   elif af == 'inet6':      
            #     new_terms.append(Term(term, 6))
          # render terms based on filter type
            
            if 3000 <= acl_number <= 3999:
              if af == 'inet':
                new_terms.append(Term(term))
              elif af == 'inet6':      
                new_terms.append(Term(term, 6))
            elif  2000 <= acl_number <= 2999:
              if af == 'inet':
                new_terms.append(TermBasic(term, filter_name, 4))
              elif af == 'inet6':      
                new_terms.append(TermBasic(term, filter_name, 6))

        self.comware_policies.append((header, filter_name, acl_number, new_terms, next_filter))
       

  def __str__(self):
    target_header = []
    target = []
    logging.debug ('comware has %d policies' , len(self.comware_policies))    
    for (header, filter_name, acl_number, terms, this_filter_type
      ) in self.comware_policies:  
      logging.debug ('comware has %d terms' , len(terms))
      if 2000 < acl_number < 3999:
        if (this_filter_type == 'inet'):         
            target.append('Undo acl number %s' % acl_number)
            target.append('Undo acl name %s' % filter_name)
            target.append('acl number %s name %s' % (acl_number, filter_name))
        if (this_filter_type == 'inet6'):
            target.append('Undo acl ipv6 number %s' % acl_number) #remove numerif name changed
            target.append('Undo acl ipv6 name %s' % filter_name) #remove name if number changed
            target.append('acl ipv6 number %s name %s' % (acl_number, filter_name))
      else:
        raise UnsupportedComwareAccessListError(
            'acl number %s not supported by %s' % (
                acl_number, self._PLATFORM))

       # add a header comment if one exists
      combined_comment = ''
      for comment in header.comment:
        for line in comment.split('\n'):
          combined_comment += ' - ' + str(line)
      target.append('description' + combined_comment[:126])
      
      # now add the terms
      for term in terms:
        target.append(str(term))
      target.append('\n')

    return '\n'.join(target)


