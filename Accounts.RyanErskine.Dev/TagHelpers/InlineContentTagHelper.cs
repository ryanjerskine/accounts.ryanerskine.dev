using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Accounts.RyanErskine.Dev.TagHelpers
{
    public class InlineContentTagHelper : TagHelper
    {
        private readonly IWebHostEnvironment _HostingEnvironment;
        private readonly IMemoryCache _Cache;

        public InlineContentTagHelper(IWebHostEnvironment hostingEnvironment, IMemoryCache cache)
        {
            this._HostingEnvironment = hostingEnvironment ?? throw new ArgumentNullException(nameof(hostingEnvironment));
            this._Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        [HtmlAttributeName("href")]
        public string Href { get; set; }

        public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            var fileContent = await this._Cache.GetOrCreateAsync($"InlineStyle-{this.Href}", async entry =>
            {
                var fileProvider = this._HostingEnvironment.WebRootFileProvider;
                var changeToken = fileProvider.Watch(this.Href);
                entry.SetPriority(CacheItemPriority.NeverRemove);
                entry.AddExpirationToken(changeToken);
                var file = fileProvider.GetFileInfo(this.Href);
                if (file == null || !file.Exists)
                    return null;
                return await ReadFileContent(file);
            });
            if (fileContent == null)
            {
                output.SuppressOutput();
                return;
            }
            output.TagName = this.Href.ToLowerInvariant().EndsWith(".css") ? "style" : "script";
            output.Attributes.RemoveAll("href");
            output.Content.AppendHtml(fileContent);
        }

        private static async Task<string> ReadFileContent(IFileInfo file)
        {
            using (var stream = file.CreateReadStream())
            using (var textReader = new StreamReader(stream))
            {
                return await textReader.ReadToEndAsync();
            }
        }
    }
}
