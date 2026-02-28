import XCTest
@testable import PhishGuardCore

final class SafeonwebBrandExtractorTests: XCTestCase {

    // MARK: - Dutch patterns

    func testInNaamVan() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in naam van Argenta")
        XCTAssertEqual(brands, ["argenta"])
    }

    func testInNaamVanDe() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in naam van de Watergroep")
        XCTAssertEqual(brands, ["watergroep"])
    }

    func testInNaamVanHet() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in naam van het Rode Kruis")
        XCTAssertEqual(brands, ["rode kruis"])
    }

    func testNamens() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Valse sms namens itsme")
        XCTAssertEqual(brands, ["itsme"])
    }

    // MARK: - English patterns

    func testInTheNameOf() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in the name of NMBS")
        XCTAssertEqual(brands, ["nmbs"])
    }

    func testInTheNameOfThe() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in the name of the National Bank")
        XCTAssertEqual(brands, ["national bank"])
    }

    // MARK: - Multi-brand

    func testMultipleBrandsWithEn() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in naam van de Watergroep en Farys")
        XCTAssertEqual(brands, ["watergroep", "farys"])
    }

    // MARK: - Edge cases

    func testNoMatch() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Tips om veilig online te blijven")
        XCTAssertTrue(brands.isEmpty)
    }

    func testTrailingPunctuation() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "Phishing in naam van Argenta.")
        XCTAssertEqual(brands, ["argenta"])
    }

    func testCaseInsensitive() {
        let brands = SafeonwebBrandExtractor.extractBrands(from: "PHISHING IN NAAM VAN ITSME")
        XCTAssertEqual(brands, ["itsme"])
    }
}
