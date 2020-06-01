#include "storages/portable_storage_to_json.h"

namespace epee {
  namespace serialization {

    void dump_as_json(std::ostream& strm, const array_entry& ae, size_t indent, bool pretty)
    {
      std::visit([&](const auto& a) {
          strm << '[';
          for (auto it = a.begin(); it != a.end(); ++it)
          {
            if (it != a.begin()) strm << ',';
            dump_as_json(strm, *it, indent, pretty);
          }
          strm << ']';
        }, ae);
    }

    void dump_as_json(std::ostream& strm, const storage_entry& se, size_t indent, bool pretty)
    {
      std::visit([&](const auto& v) {
          dump_as_json(strm, v, indent, pretty);
        }, se);
    }

    void dump_as_json(std::ostream& s, const std::string& v, size_t, bool)
    {
      s << '"';
      // JSON strings may only contain 0x20 and above, except for " and \\ which must be escaped.
      // For values below 0x20 we can use \u00XX escapes, except for the really common \n and \t (we
      // could also use \b, \f, \r, but it really isn't worth the bother.
      for (char c : v) {
        switch(c) {
          case '"':
          case '\\':
            s << '\\' << c;
            break;
          case '\n': s << "\\n"; break;
          case '\t': s << "\\t"; break;
          case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
          case 0x08: /*\t=0x09: \n=0x0a*/  case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
          case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
          case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
            s << "\\u00" << (c >= 0x10 ? '1' : '0');
            c &= 0xf;
            s << (c < 0xa ? '0' + c : ('a' - 10) + c);
            break;
          default:
            s << c;
        }
      }
      s << '"';
    }


    void dump_as_json(std::ostream& strm, const section& sec, size_t indent, bool pretty)
    {
      strm << '{';
      if(sec.m_entries.empty())
        strm << '}';
      else
      {
        size_t local_indent = indent + 1;
        std::string line_sep(pretty * (1 + 2*local_indent), ' ');
        if (pretty) line_sep[0] = '\n';

        for (auto it = sec.m_entries.begin(); it != sec.m_entries.end(); ++it)
        {
          if (it != sec.m_entries.begin()) strm << ',';
          strm << line_sep;
          dump_as_json(strm, it->first, local_indent, pretty);
          strm << ':';
          if (pretty) strm << ' ';
          dump_as_json(strm, it->second, local_indent, pretty);
        }
        if (pretty)
          line_sep.resize(line_sep.size() - 2);
        strm << line_sep << '}';
      }
    }

  }
}
