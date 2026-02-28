import Foundation

/// A parsed article from the Safeonweb RSS feed.
public struct SafeonwebArticle {
    public let title: String
    public let pubDate: Date

    public init(title: String, pubDate: Date) {
        self.title = title
        self.pubDate = pubDate
    }
}

/// Parses Safeonweb RSS feed XML, extracting `<title>` and `<pubDate>` from `<item>` elements.
public final class SafeonwebRSSParser: NSObject, XMLParserDelegate {
    private var articles: [SafeonwebArticle] = []
    private var currentElement = ""
    private var currentTitle = ""
    private var currentPubDate = ""
    private var insideItem = false

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter
    }()

    /// Parses RSS XML data and returns the extracted articles.
    public func parse(data: Data) -> [SafeonwebArticle] {
        articles = []
        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.parse()
        return articles
    }

    // MARK: - XMLParserDelegate

    public func parser(_ parser: XMLParser, didStartElement elementName: String,
                       namespaceURI: String?, qualifiedName: String?,
                       attributes: [String: String] = [:]) {
        currentElement = elementName
        if elementName == "item" {
            insideItem = true
            currentTitle = ""
            currentPubDate = ""
        }
    }

    public func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard insideItem else { return }
        switch currentElement {
        case "title":
            currentTitle += string
        case "pubDate":
            currentPubDate += string
        default:
            break
        }
    }

    public func parser(_ parser: XMLParser, didEndElement elementName: String,
                       namespaceURI: String?, qualifiedName: String?) {
        if elementName == "item" {
            insideItem = false
            let title = currentTitle.trimmingCharacters(in: .whitespacesAndNewlines)
            let dateString = currentPubDate.trimmingCharacters(in: .whitespacesAndNewlines)
            let date = Self.dateFormatter.date(from: dateString) ?? Date()

            if !title.isEmpty {
                articles.append(SafeonwebArticle(title: title, pubDate: date))
            }
        }
        currentElement = ""
    }
}
