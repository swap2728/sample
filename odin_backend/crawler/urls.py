"""
URL configuration for odin_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from crawler.views import (
    CrawlView, SystemInfoView, DuckDuckGoSearchView, DarkWebSearchView, 
    FileDataExtractionView, TextOptionView, ImageSearchView, DorkSearchView,
    SingleImageDownloadView, FileDataView, AESEncryptionView, PacketCaptureView,
    VulnerabilityScanView,AudioProcessingView,TextTranslationView,DarkWebOperationView,
    TorStatusView, ProcessSubscriptionView, 
    CheckAccessView,ScanView

)

urlpatterns = [
    path("api/crawl/", CrawlView.as_view(), name="crawl_api"),
    path("api/system-info/", SystemInfoView.as_view(), name="system_info"),
    path("api/duckduckgo-search/", DuckDuckGoSearchView.as_view(), name="duckduckgo_search"),
    path("api/dark-web-search/", DarkWebSearchView.as_view(), name="dark_web_search"),
    path("api/file-data-extraction/", FileDataExtractionView.as_view(), name="file_data_extraction"),
    path("api/text-option/", TextOptionView.as_view(), name="text_option"),
    path("api/search-image/",ImageSearchView.as_view(),name="search-image"),
    path("api/dork-search/",DorkSearchView.as_view(), name="dork_search"),
    path('api/download-single-image/', SingleImageDownloadView.as_view(), name='download-single-image'),
    path('api/file-data/', FileDataView.as_view(), name='file-data'),

    path('api/aes-encryption/', AESEncryptionView.as_view(), name='aes-encryption'),
    path('api/capture-packets/', PacketCaptureView.as_view(), name='capture-packets'),
    path('api/vulnerability-scan/', VulnerabilityScanView.as_view(), name='vulnerability-scan'),

    path('api/audio-process/', AudioProcessingView.as_view(), name='audio-process'),
    path('api/translate-text/', TextTranslationView.as_view(), name='translate-text'),

    path('api/dark-web/', DarkWebOperationView.as_view(), name='darkweb_api'),
    path('api/tor-status/', TorStatusView.as_view(), name='tor_status'),

    path('check-access/', CheckAccessView.as_view(), name='check-access'),
    path('process-subscription/', ProcessSubscriptionView.as_view(), name='process-subscription'),

    path('api/scan/', ScanView.as_view(), name='scan'),
]