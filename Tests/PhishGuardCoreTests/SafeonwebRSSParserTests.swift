import XCTest
@testable import PhishGuardCore

final class SafeonwebRSSParserTests: XCTestCase {
    let parser = SafeonwebRSSParser()

    func testParseItems() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Safeonweb</title>
            <item>
              <title>Phishing in naam van Argenta</title>
              <pubDate>Mon, 10 Feb 2025 10:00:00 +0100</pubDate>
            </item>
            <item>
              <title>Valse sms namens itsme</title>
              <pubDate>Tue, 11 Feb 2025 14:30:00 +0100</pubDate>
            </item>
          </channel>
        </rss>
        """
        let data = xml.data(using: .utf8)!
        let articles = parser.parse(data: data)

        XCTAssertEqual(articles.count, 2)
        XCTAssertEqual(articles[0].title, "Phishing in naam van Argenta")
        XCTAssertEqual(articles[1].title, "Valse sms namens itsme")
    }

    func testEmptyFeed() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Safeonweb</title>
          </channel>
        </rss>
        """
        let data = xml.data(using: .utf8)!
        let articles = parser.parse(data: data)

        XCTAssertTrue(articles.isEmpty)
    }

    func testParseDateCorrectly() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Test article</title>
              <pubDate>Wed, 01 Jan 2025 12:00:00 +0000</pubDate>
            </item>
          </channel>
        </rss>
        """
        let data = xml.data(using: .utf8)!
        let articles = parser.parse(data: data)

        XCTAssertEqual(articles.count, 1)
        // Verify the date is Jan 1 2025 12:00 UTC
        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(in: TimeZone(identifier: "UTC")!, from: articles[0].pubDate)
        XCTAssertEqual(components.year, 2025)
        XCTAssertEqual(components.month, 1)
        XCTAssertEqual(components.day, 1)
    }
}
