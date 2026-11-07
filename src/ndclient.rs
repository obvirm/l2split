//! ndclient — klien driver packet filter untuk engine l2split.
//!
//! Driver ini tertanda-tangani WHQL oleh Microsoft, jadi tampil di semua
//! Windows tanpa test signing dan tanpa menyentuh Secure Boot.
//! Engine memakai dua primitif:
//!   - capture: STATIC_FILTER (dst-MAC = gateway VPN, arah TX, action REDIRECT)
//!     — hanya frame yang menarik yang ditahan ke user-mode, sisanya lewat
//!     sisi kernel tanpa disentuh;
//!   - reinject: send_packets_to_adapter (arah asli) dan send_packets_to_adapter
//!     pada adapter LAN (arah bypass).
use ndisapi::{
    DataLinkLayerFilter, DataLinkLayerFilterUnion, DirectionFlags, Eth8023Filter,
    Eth802_3FilterFlags, EthMRequestMut, FilterFlags, FilterLayerFlags,
    FILTER_PACKET_PASS, FILTER_PACKET_REDIRECT, IntermediateBuffer, Ndisapi, StaticFilter,
    StaticFilterTable, ETH_802_3,
};
use windows::Win32::Foundation::HANDLE;

/// Satu adapter TCP/IP-bound dari driver.
pub struct SniAdapter {
    /// Nama friendly (dari registry; contoh "Ethernet 2").
    pub name: String,
    /// MAC adapter (hex, sebagaimana driver laporkan).
    pub mac: [u8; 6],
    /// HANDLE driver untuk opera read/inject per adapter.
    pub handle: HANDLE,
}

unsafe impl Send for SniAdapter {}
unsafe impl Sync for SniAdapter {}

/// HANDLE adapter yang aman dikirim ke thread lain (nilainya dibuat oleh
/// driver sendiri dan dioper apa adanya).
#[derive(Copy, Clone)]
pub struct AdapterHandle(pub HANDLE);

unsafe impl Send for AdapterHandle {}
unsafe impl Sync for AdapterHandle {}

/// Ukuran batch read/inject.
pub const BATCH: usize = 256;

pub struct NdisDevice {
    inner: Ndisapi,
}

unsafe impl Send for NdisDevice {}
unsafe impl Sync for NdisDevice {}

impl NdisDevice {
    /// Buka handel driver. Gagal = driver belum terpasang.
    pub fn open() -> Result<Self, String> {
        let inner = Ndisapi::new("NDISRD")
            .map_err(|e| format!("driver belum siap: {e} — jalankan wizard instalasi driver dulu"))?;
        Ok(Self { inner })
    }

    /// Daftar adapter yang terb ива ke TCP/IP (nama friendly + MAC).
    pub fn adapters(&self) -> Result<Vec<SniAdapter>, String> {
        let list = self
            .inner
            .get_tcpip_bound_adapters_info()
            .map_err(|e| format!("enumerate: {e}"))?;
        let mut out = Vec::new();
        for a in list.iter() {
            let raw = a.get_name().to_string();
            let name = Ndisapi::get_friendly_adapter_name(raw.clone())
                .unwrap_or(raw)
                .trim()
                .to_string();
            out.push(SniAdapter {
                name,
                mac: *a.get_hw_address(),
                handle: a.get_handle(),
            });
        }
        Ok(out)
    }

    /// Pasang filter kernel: semua TX ke dst_mac diumpankan ke user-mode
    /// (REDIRECT). Frame lain jalan melancong tanpa menyentuh user-mode.
    /// Baris PASS default wajib — tanpa itu frame yang tak match di-drop.
    pub fn capture_tx(&self, dst_mac: [u8; 6]) -> Result<(), String> {
        let filter = StaticFilter::new(
            0u64,
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::DATA_LINK_LAYER_VALID,
            DataLinkLayerFilter::new(
                ETH_802_3,
                DataLinkLayerFilterUnion {
                    eth_8023_filter: Eth8023Filter::new(
                        Eth802_3FilterFlags::ETH_802_3_DEST_ADDRESS,
                        [0u8; 6],
                        dst_mac,
                        0u16,
                    ),
                },
            ),
            ndisapi::NetworkLayerFilter::default(),
            ndisapi::TransportLayerFilter::default(),
        );
        let pass_all = StaticFilter::new(
            0u64,
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            ndisapi::NetworkLayerFilter::default(),
            ndisapi::TransportLayerFilter::default(),
        );
        let table = StaticFilterTable::<2>::from_filters([filter, pass_all]);
        self.inner
            .set_packet_filter_table(&table)
            .map_err(|e| format!("set_filter: {e}"))
    }

    /// Pasang filter kernel: SEMUA TX frame diumpankan ke user-mode (REDIRECT)
    /// + baris PASS default. Diagnostik apakah jalur TX LWF hidup sama sekali.
    pub fn capture_tx_all(&self) -> Result<(), String> {
        let all = StaticFilter::new(
            0u64,
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_REDIRECT,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            ndisapi::NetworkLayerFilter::default(),
            ndisapi::TransportLayerFilter::default(),
        );
        let pass_all = StaticFilter::new(
            0u64,
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            ndisapi::NetworkLayerFilter::default(),
            ndisapi::TransportLayerFilter::default(),
        );
        let table = StaticFilterTable::<2>::from_filters([all, pass_all]);
        self.inner
            .set_packet_filter_table(&table)
            .map_err(|e| format!("set_filter: {e}"))
    }

    /// Tabel pass-all (semua frame masuk & lewat kernel tanpa disentuh).
    pub fn capture_pass(&self) -> Result<(), String> {
        let pass_all = StaticFilter::new(
            0u64,
            DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_PASS,
            FilterLayerFlags::empty(),
            DataLinkLayerFilter::default(),
            ndisapi::NetworkLayerFilter::default(),
            ndisapi::TransportLayerFilter::default(),
        );
        let table = StaticFilterTable::<1>::from_filters([pass_all]);
        self.inner
            .set_packet_filter_table(&table)
            .map_err(|e| format!("set_filter: {e}"))
    }

    /// Mode adapter: frame MSTCP ditahan ke antrian user-mode (uji/lap).
    pub fn tunnel_tx(&self, handle: HANDLE) -> Result<(), String> {
        self.inner
            .set_adapter_mode(handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)
            .map_err(|e| format!("mode: {e}"))
    }

    /// Kembalikan mode adapter ke default.
    pub fn restore_mode(&self, handle: HANDLE) {
        let _ = self.inner.set_adapter_mode(handle, FilterFlags::default());
    }

    /// Kosongkan tabel filter kernel (saat engine berhenti).
    pub fn clear(&self) {
        let _ = self.inner.reset_packet_filter_table();
    }

    /// Daftarkan event Win32 untuk sinyal bantal per adapter.
    pub fn set_event(&self, handle: HANDLE, ev: HANDLE) -> Result<(), String> {
        self.inner
            .set_packet_event(handle, ev)
            .map_err(|e| format!("set_event: {e}"))
    }

    /// Baca satu batch frame adapter (paling banyak BATCH).
    pub fn read_batch(
        &self,
        handle: HANDLE,
        bufs: &mut [IntermediateBuffer],
    ) -> usize {
        let mut req = EthMRequestMut::<BATCH>::from_iter(handle, bufs.iter_mut());
        self.inner.read_packets::<BATCH>(&mut req).unwrap_or(0)
    }

    /// Baca dengan laporan error eksplisit (diagnostik).
    pub fn read_batch_err(
        &self,
        handle: HANDLE,
        bufs: &mut [IntermediateBuffer],
    ) -> Result<usize, String> {
        let mut req = EthMRequestMut::<BATCH>::from_iter(handle, bufs.iter_mut());
        self.inner
            .read_packets::<BATCH>(&mut req)
            .map_err(|e| format!("read: {e}"))
    }

    /// Lihat berapa frame menunggu di antrian adapter.
    pub fn queue_size(&self, handle: HANDLE) -> Result<u32, String> {
        self.inner
            .get_adapter_packet_queue_size(handle)
            .map_err(|e| format!("queue_size: {e}"))
    }

    /// Kirim satu batch frame ke adapter yakni request sudah berisi.
    pub fn send_batch(
        &self,
        req: &ndisapi::EthMRequest<'_, BATCH>,
    ) -> Result<(), String> {
        self.inner
            .send_packets_to_adapter::<BATCH>(req)
            .map_err(|e| format!("send_batch: {e}"))
    }
}
