package dns

import java.net.InetSocketAddress

/**
 * Validated bootstrap addresses extracted from an RFC-style root hints file.
 *
 * Only address records whose owners occur in the root NS RRset are accepted; unrelated records
 * cannot become bootstrap servers.
 */
final case class RootHints private (
    nameServers: Vector[DomainName],
    addresses: Vector[InetSocketAddress]
)

object RootHints:
  enum Error derives CanEqual:
    case Syntax(diagnostics: Vector[ZoneFile.Diagnostic])
    case MissingRootNameServers
    case MissingAddresses(nameServers: Vector[DomainName])

  /** Parses the master-file format published by Internic. */
  def parse(input: String): Either[Error, RootHints] = ZoneFile.parseRecords(input, DomainName.Root)
    .left.map(Error.Syntax.apply).flatMap { records =>
      val nameServers =
        records.collect {
          case ResourceRecord(DomainName.Root, RecordClass.IN, _, RecordData.NS(target)) => target
        }.distinct
      if nameServers.isEmpty then Left(Error.MissingRootNameServers)
      else
        val eligible = nameServers.toSet
        val addresses =
          records.flatMap {
            case ResourceRecord(owner, RecordClass.IN, _, RecordData.A(address))
                if eligible.contains(owner) =>
              Some(new InetSocketAddress(address, 53))
            case ResourceRecord(owner, RecordClass.IN, _, RecordData.AAAA(address))
                if eligible.contains(owner) =>
              Some(new InetSocketAddress(address, 53))
            case _ => None
          }.distinct
        if addresses.isEmpty then Left(Error.MissingAddresses(nameServers))
        else Right(new RootHints(nameServers, addresses))
    }
