package dns

import scala.collection.mutable.ArrayBuffer

/** Bounded lexical layer for RFC 1035 master files. */
private[dns] object ZoneFileSyntax:
  final case class Statement(line: Int, ownerOmitted: Boolean, tokens: Vector[String])

  def statements(
      input: String,
      maxLogicalLineLength: Int
  ): Either[Vector[ZoneFile.Diagnostic], Vector[Statement]] =
    val result = Vector.newBuilder[Statement]
    val errors = Vector.newBuilder[ZoneFile.Diagnostic]
    val logical = new StringBuilder
    var startLine = 1
    var ownerOmitted = false
    var parentheses = 0
    var quoted = false

    input.linesIterator.zipWithIndex.foreach { (physical, index) =>
      val line = index + 1
      if logical.isEmpty then
        startLine = line
        ownerOmitted = physical.headOption.exists(_.isWhitespace)
      val cleaned = stripComment(physical)
      cleaned.foreach {
        case '"' =>
          quoted = !quoted
          logical += '"'
        case '(' if !quoted =>
          parentheses += 1
          logical += ' '
        case ')' if !quoted =>
          parentheses -= 1
          if parentheses < 0 then
            errors += ZoneFile.Diagnostic(line, "unexpected closing parenthesis")
            parentheses = 0
          logical += ' '
        case character => logical += character
      }
      if logical.length > maxLogicalLineLength then
        errors +=
          ZoneFile.Diagnostic(startLine, s"logical line exceeds $maxLogicalLineLength bytes")
        logical.clear()
        parentheses = 0
        quoted = false
      else if parentheses == 0 && !quoted then
        tokenize(logical.result(), startLine) match
          case Right(tokens) if tokens.nonEmpty =>
            result += Statement(startLine, ownerOmitted, tokens)
          case Right(_)    => ()
          case Left(error) => errors += error
        logical.clear()
      else logical += ' '
    }

    if quoted then errors += ZoneFile.Diagnostic(startLine, "unterminated quoted string")
    if parentheses != 0 then errors += ZoneFile.Diagnostic(startLine, "unterminated parentheses")
    val diagnostics = errors.result()
    if diagnostics.nonEmpty then Left(diagnostics) else Right(result.result())

  private def stripComment(line: String): String =
    val output = new StringBuilder
    var quoted = false
    var escaped = false
    var index = 0
    var done = false
    while index < line.length && !done do
      val character = line(index)
      if escaped then
        output += character
        escaped = false
      else
        character match
          case '\\' =>
            output += character
            escaped = true
          case '"' =>
            output += character
            quoted = !quoted
          case ';' if !quoted => done = true
          case _              => output += character
      index += 1
    output.result()

  private def tokenize(value: String, line: Int): Either[ZoneFile.Diagnostic, Vector[String]] =
    val tokens = ArrayBuffer.empty[String]
    val token = new StringBuilder
    var quoted = false
    var index = 0

    def finish(): Unit =
      if token.nonEmpty then
        tokens += token.result()
        token.clear()

    while index < value.length do
      value(index) match
        case '"'                                            => quoted = !quoted
        case character if character.isWhitespace && !quoted => finish()
        case '\\'                                           =>
          if index + 1 >= value.length then
            return Left(ZoneFile.Diagnostic(line, "trailing escape"))
          val digits = value.slice(index + 1, math.min(index + 4, value.length))
          if digits.length == 3 && digits.forall(_.isDigit) then
            val decoded = digits.toInt
            if decoded > 255 then
              return Left(ZoneFile.Diagnostic(line, s"decimal escape out of range: $decoded"))
            token += decoded.toChar
            index += 3
          else
            index += 1
            token += value(index)
        case character => token += character
      index += 1
    finish()
    if quoted then Left(ZoneFile.Diagnostic(line, "unterminated quoted string"))
    else Right(tokens.toVector)
