
using CertificateCommon;
using Microsoft.AspNetCore.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UT
{
    [TestClass]
    public class ConversionTests
    {
        // Fake implementation of IFormFile for testing purposes
        public class FakeFormFile : IFormFile
        {
            private readonly byte[] _content;

            public FakeFormFile(string content)
            {
                _content = Encoding.UTF8.GetBytes(content);
            }

            public Stream OpenReadStream()
            {
                return new MemoryStream(_content);
            }

            // Not implemented members required by interface
            public string ContentType => "text/plain";
            public string ContentDisposition => "form-data";
            public IHeaderDictionary Headers => null!;
            public long Length => _content.Length;
            public string Name => "file";
            public string FileName => "test.txt";
            public void CopyTo(Stream target) => throw new NotImplementedException();
            public Task CopyToAsync(Stream target, CancellationToken cancellationToken = default) 
            {
                var stream = OpenReadStream();
                return stream.CopyToAsync(target, cancellationToken);
            }
        }

        [TestMethod]
        public async Task ConvertIFormFileToByteArrayAsync_ShouldReturnNull_When_FileIsNull()
        {
            // Arrange
            // Using the simple constructor with explicit values to avoid config dependency
            // Passing a dummy thumbprint reduces side effects as it likely won't find a match, setting CARoot to null, which is fine here.
            var manager = new CertificationManager("dummy-thumbprint", 0);

            // Act
            // We expect this to return null. Currently it does so by catching the NullReferenceException.
            // We will refactor to make it explicit.
            var result = await manager.ConvertIFormFileToByteArrayAsync(null);

            // Assert
            Assert.IsNull(result, "Should return null when input IFormFile is null");
        }

        [TestMethod]
        public async Task ConvertIFormFileToByteArrayAsync_ShouldReturnByteArray_When_FileIsValid()
        {
            // Arrange
            var manager = new CertificationManager("dummy-thumbprint", 0);
            string testContent = "Hello World";
            var fakeFile = new FakeFormFile(testContent);

            // Act
            var result = await manager.ConvertIFormFileToByteArrayAsync(fakeFile);

            // Assert
            Assert.IsNotNull(result);
            string resultString = Encoding.UTF8.GetString(result);
            Assert.AreEqual(testContent, resultString);
        }
    }
}
