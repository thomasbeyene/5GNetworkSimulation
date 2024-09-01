//
// Generated file, do not edit! Created by opp_msgtool 6.0 from inet/networklayer/ted/LinkStatePacket.msg.
//

#ifndef __INET_LINKSTATEPACKET_M_H
#define __INET_LINKSTATEPACKET_M_H

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif
#include <omnetpp.h>

// opp_msgtool version check
#define MSGC_VERSION 0x0600
#if (MSGC_VERSION!=OMNETPP_VERSION)
#    error Version mismatch! Probably this file was generated by an earlier version of opp_msgtool: 'make clean' should help.
#endif

// dll export symbol
#ifndef INET_API
#  if defined(INET_EXPORT)
#    define INET_API  OPP_DLLEXPORT
#  elif defined(INET_IMPORT)
#    define INET_API  OPP_DLLIMPORT
#  else
#    define INET_API
#  endif
#endif


namespace inet {

class LinkStateMsg;

}  // namespace inet

#include "inet/common/INETDefs_m.h" // import inet.common.INETDefs

#include "inet/common/packet/chunk/Chunk_m.h" // import inet.common.packet.chunk.Chunk

#include "inet/networklayer/ted/Ted_m.h" // import inet.networklayer.ted.Ted


namespace inet {

/**
 * Class generated from <tt>inet/networklayer/ted/LinkStatePacket.msg:19</tt> by opp_msgtool.
 * <pre>
 * //
 * // Packet for disseminating link state information (~TeLinkStateInfo[]) by the
 * // ~LinkStateRouting module which implements a minimalistic link state routing
 * // protocol.
 * //
 * class LinkStateMsg extends FieldsChunk
 * {
 *     TeLinkStateInfo linkInfo[];
 * 
 *     bool request = false; // if true, receiver is expected to send back its own link state database to the sender --FIXME really needed?
 *         // bool ack = false; -- apparently unused, removed -- TODO check with Vojta
 * 
 *     int command = 1; // FIXME maybe do without this...
 * }
 * </pre>
 */
class INET_API LinkStateMsg : public ::inet::FieldsChunk
{
  protected:
    TeLinkStateInfo *linkInfo = nullptr;
    size_t linkInfo_arraysize = 0;
    bool request = false;
    int command = 1;

  private:
    void copy(const LinkStateMsg& other);

  protected:
    bool operator==(const LinkStateMsg&) = delete;

  public:
    LinkStateMsg();
    LinkStateMsg(const LinkStateMsg& other);
    virtual ~LinkStateMsg();
    LinkStateMsg& operator=(const LinkStateMsg& other);
    virtual LinkStateMsg *dup() const override {return new LinkStateMsg(*this);}
    virtual void parsimPack(omnetpp::cCommBuffer *b) const override;
    virtual void parsimUnpack(omnetpp::cCommBuffer *b) override;

    virtual void setLinkInfoArraySize(size_t size);
    virtual size_t getLinkInfoArraySize() const;
    virtual const TeLinkStateInfo& getLinkInfo(size_t k) const;
    virtual TeLinkStateInfo& getLinkInfoForUpdate(size_t k) { handleChange();return const_cast<TeLinkStateInfo&>(const_cast<LinkStateMsg*>(this)->getLinkInfo(k));}
    virtual void setLinkInfo(size_t k, const TeLinkStateInfo& linkInfo);
    virtual void insertLinkInfo(size_t k, const TeLinkStateInfo& linkInfo);
    [[deprecated]] void insertLinkInfo(const TeLinkStateInfo& linkInfo) {appendLinkInfo(linkInfo);}
    virtual void appendLinkInfo(const TeLinkStateInfo& linkInfo);
    virtual void eraseLinkInfo(size_t k);

    virtual bool getRequest() const;
    virtual void setRequest(bool request);

    virtual int getCommand() const;
    virtual void setCommand(int command);
};

inline void doParsimPacking(omnetpp::cCommBuffer *b, const LinkStateMsg& obj) {obj.parsimPack(b);}
inline void doParsimUnpacking(omnetpp::cCommBuffer *b, LinkStateMsg& obj) {obj.parsimUnpack(b);}


}  // namespace inet


namespace omnetpp {

template<> inline inet::LinkStateMsg *fromAnyPtr(any_ptr ptr) { return check_and_cast<inet::LinkStateMsg*>(ptr.get<cObject>()); }

}  // namespace omnetpp

#endif // ifndef __INET_LINKSTATEPACKET_M_H

