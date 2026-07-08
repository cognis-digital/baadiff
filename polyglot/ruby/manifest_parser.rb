# frozen_string_literal: true

require 'json'
require 'yaml'
require 'fileutils'
require 'open3'

module Baadiff
  module ManifestParser
    # HIPAA Security Rule categories and their sub-controls
    HIPAA_CATEGORIES = {
      access_control: [
        'unique_user_id', 'emergency_access', 'automatic_logoff',
        'least_privilege', 'periodic_review', 'shared_access'
      ],
      audit_controls: ['activity_logs', 'log_integrity'],
      integrity_controls: ['digital_signatures', 'checksums'],
      authentication: ['mfa_required', 'strong_password_policy'],
      transmission_protection: ['tls_12_minimum', 'encryption_in_transit'],
      maintenance: ['patch_management', 'configuration_change_control'],
      physical_environment: ['facility_access', 'device_security'],
      risk_analysis: ['initial_assessment', 'ongoing_review'],
      risk_management: ['threat_identification', 'safeguard_implementation']
    }.freeze

    # Resource-to-control mapping for common IAC patterns
    RESOURCE_CONTROL_MAP = {
      terraform: {
        aws_iam_user: :authentication,
        aws_iam_policy: :access_control,
        aws_s3_bucket: [:transmission_protection, :access_control],
        aws_rds_instance: [:transmission_protection, :audit_controls],
        aws_security_group: :access_control,
        aws_kms_key: :transmission_protection,
        aws_cloudtrail: :audit_controls,
        kubernetes_namespace: :authentication,
        kubernetes_service_account: :access_control,
        docker_registry: [:transmission_protection, :physical_environment]
      }.freeze,
    }.freeze

    class << self
      # Main entry point for parsing a manifest directory
      def parse_manifest(manifest_path)
        return {} unless File.directory?(manifest_path)

        files = Dir.glob("#{manifest_path}/**/*.{tf,hcl,yaml,yml,json}")
        results = {
          total_files: 0,
          parsed_files: 0,
          controls_found: Hash.new(0),
          gaps: [],
          scorecard: {}
        }

        files.each do |file|
          next unless File.file?(file)

          results[:total_files] += 1
          content = File.read(file)
          
          # Detect file type and parse accordingly
          if content.include?('resource "aws_iam') || content.include?('module "aws_iam')
            results[:parsed_files] += 1
            results.merge!(parse_terraform(content, file))
          elsif content.include?(':Resources:') && (content.include?('AWS::IAM') || content.include?('AWS::S3'))
            results[:parsed_files] += 1
            results.merge!(parse_cloudformation(content, file))
          else
            # Try generic YAML/JSON parsing for other IAC tools
            if content.start_with?('- ') || content.match?(/^\s*[\w\-]+:/)
              begin
                data = YAML.safe_load(content) || JSON.parse(content)
                results[:parsed_files] += 1
                results.merge!(parse_generic(data, file))
              rescue StandardError
                # Fallback to regex-based parsing
                results.merge!(parse_regex_based(content, file))
              end
            end
          end
        end

        # Calculate final scorecard
        results[:scorecard] = calculate_scorecard(results)

        results
      end

      private

      def parse_terraform(content, filename)
        controls_found = Hash.new(0)
        gaps = []

        # Parse Terraform resource blocks
        resources = extract_resources(content)
        
        resources.each do |resource|
          next unless resource[:type] && resource[:name]

          control_category = RESOURCE_CONTROL_MAP[:terraform][resource[:type]] || :access_control
          
            controls_found[control_category] += 1
            
              # Check for common HIPAA gaps in Terraform resources
              check_terraform_gaps(resource, filename, gaps)
          end

        {
          file: filename,
          resource_count: resources.size,
          controls_found: controls_found.transform_values(&:to_i),
          gaps: gaps
        }
      end

      def extract_resources(content)
        # Extract resource blocks from Terraform HCL
        pattern = /resource\s+"([^"]+)"\s+"([^"]+)"/m
        resources = []

        content.scan(pattern).each do |type, name|
          resources << { type: type, name: name }
        end

        # Also try to extract from modules
        module_pattern = /module\s+"([^"]+)"\s+\{[^}]*resource\s+"([^"]+)"/m
        content.scan(module_pattern).each do |_, _, resource_type|
          resources << { type: "module.#{resource_type}", name: 'module' }
        end

        resources.compact.uniq
      end

      def check_terraform_gaps(resource, filename, gaps)
        type = resource[:type]
        name = resource[:name]

        case type
        when /aws_s3_bucket/
          # Check for encryption at rest
          if !content.include?('encryption') && !content.include?('server_side_encryption_configuration')
            gaps << { category: :transmission_protection, rule: 'S3 Server-Side Encryption', file: filename }
          end

        when /aws_iam_user/
          # Check for MFA requirement
          if !content.include?('mfa_enabled') && !content.include?('login_profile')
            gaps << { category: :authentication, rule: 'IAM User MFA', file: filename }
          end

        when /aws_rds_instance/
          # Check for encryption in transit
          if !content.include?('transport_encryption') || content.match?(/transport_encryption\s*=\s*"none"/)
            gaps << { category: :transmission_protection, rule: 'RDS Transport Encryption', file: filename }
          end

        when /aws_cloudtrail/
          # Check for log integrity settings
          if !content.include?('is_multi_region_trail_enabled') || content.match?(/is_multi_region_trail_enabled\s*=\s*false/)
            gaps << { category: :audit_controls, rule: 'CloudTrail Multi-Region', file: filename }
          end

        when /kubernetes_namespace/
          # Check for service account restrictions
          if !content.include?('service_account') && !content.include?('automount_service_account_token')
            gaps << { category: :access_control, rule: 'K8s Service Account Token Auto-Mount', file: filename }
          end

        when /docker_registry/
          # Check for TLS configuration
          if !content.include?('tls_enabled') || content.match?(/tls_enabled\s*=\s*false/)
            gaps << { category: :transmission_protection, rule: 'Docker Registry TLS', file: filename }
          end

        else
          # Default gap check - look for common patterns
          if !content.include?('security') && !content.include?('encrypt')
            gaps << { category: :access_control, rule: 'General Security Configuration', file: filename }
          end
        end
      end

      def parse_cloudformation(content, filename)
        controls_found = Hash.new(0)
        gaps = []

        # Parse CloudFormation resources
        resources = extract_cf_resources(content)

        resources.each do |resource|
          next unless resource[:type] && resource[:properties]

          control_category = RESOURCE_CONTROL_MAP[:terraform][resource[:type]] || :access_control
          
            controls_found[control_category] += 1
            
              check_cloudformation_gaps(resource, filename, gaps)
          end

        {
          file: filename,
          resource_count: resources.size,
          controls_found: controls_found.transform_values(&:to_i),
          gaps: gaps
        }
      end

      def extract_cf_resources(content)
        pattern = /"Resources":\s*\{([^}]+)\}/m
        match = content.match(pattern)
        
        return [] unless match
        
        resources = []
        resource_blocks = match[1].split(/,\s*"/).map do |block|
          type_match = block.match(/"Type"\s*:\s*"([^"]+)"/)
          next nil unless type_match
          
          { type: type_match[1], properties: {} }
        end.compact

        resources
      end

      def check_cloudformation_gaps(resource, filename, gaps)
        type = resource[:type]

        case type
        when /AWS::IAM::User/
          if !resource[:properties].key?('LoginProfile') || !resource[:properties]['LoginProfile'].is_a?(Array)
            gaps << { category: :authentication, rule: 'IAM User Login Profile', file: filename }
          end

        when /AWS::S3::Bucket/
          if !resource[:properties].key?('ServerSideEncryptionConfiguration')
            gaps << { category: :transmission_protection, rule: 'S3 Bucket Encryption', file: filename }
          end

        when /AWS::RDS::DBInstance/
          if !resource[:properties].key?('StorageEncrypted') || resource[:properties]['StorageEncrypted'] != true
            gaps << { category: :transmission_protection, rule: 'RDS Storage Encryption', file: filename }
          end

        when /AWS::CloudTrail::Trail/
          if !resource[:properties].key?('IsMultiRegionTrail') || resource[:properties]['IsMultiRegionTrail'] != true
            gaps << { category: :audit_controls, rule: 'CloudTrail Multi-Region', file: filename }
          end

        when /AWS::KMS::Key/
          if !resource[:properties].key?('EnableKeyRotation') || resource[:properties]['EnableKeyRotation'] != true
            gaps << { category: :transmission_protection, rule: 'KMS Key Rotation', file: filename }
          end

        else
          # Generic check for encryption-related properties
          if type.include?('Encryption') && !resource[:properties].key?('Enabled') || resource[:properties]['Enabled'] != true
            gaps << { category: :transmission_protection, rule: "Encryption in #{type}", file: filename }
          end
        end
      end

      def parse_generic(data, filename)
        controls_found = Hash.new(0)
        gaps = []

        # Try to identify resource types from generic YAML/JSON
        if data.is_a?(Hash)
          resources = extract_generic_resources(data)

          resources.each do |resource|
            next unless resource[:type]

            control_category = RESOURCE_CONTROL_MAP[:terraform][resource[:type]] || :access_control
            
              controls_found[control_category] += 1
            
                check_generic_gaps(resource, filename, gaps)
          end

        {
          file: filename,
          resource_count: resources.size,
          controls_found: controls_found.transform_values(&:to_i),
          gaps: gaps
        }
      end

      def extract_generic_resources(data)
        resources = []

        if data.is_a?(Hash)
          # Look for common IAC patterns in generic YAML/JSON
          data.each do |key, value|
            next unless key.to_s.include?('resource') || key.to_s.include?('Resource')

            type_match = key.match(/(\w+)\s*:\s*(\w+)/i)
            resources << { type: type_match ? "#{type_match[1]}.#{type_match[2]}" : 'unknown', properties: value } if type_match
          end
        elsif data.is_a?(Array)
          # Handle array of resource definitions
          data.each do |item|
            next unless item.is_a?(Hash)

            type_match = item.key?('Type') || item.key?('type')
            resources << { type: type_match.to_s, properties: item } if type_match
          end
        end

        resources.compact.uniq
      end

      def check_generic_gaps(resource, filename, gaps)
        type = resource[:type]

        # Check for encryption in generic resources
        if type.include?('S3') || type.include?('Bucket')
          if !resource[:properties].key?('ServerSideEncryptionConfiguration') && !resource[:properties].key?('server_side_encryption_configuration')
            gaps << { category: :transmission_protection, rule: 'Generic S3 Encryption', file: filename }
          end
        elsif type.include?('IAM') || type.include?('User')
          if !resource[:properties].key?('MfaEnabled') && !resource[:properties].key?('mfa_enabled')
            gaps << { category: :authentication, rule: 'Generic IAM MFA', file: filename }
          end
        elsif type.include?('RDS') || type.include?('Database')
          if !resource[:properties].key?('StorageEncrypted') && !resource[:properties].key?('storage_encrypted')
            gaps << { category: :transmission_protection, rule: 'Generic RDS Encryption', file: filename }
          end
        elsif type.include?('CloudTrail') || type.include?('Audit')
          if !resource[:properties].key?('IsMultiRegionTrail') && !resource[:properties].key?('is_multi_region_trail_enabled')
            gaps << { category: :audit_controls, rule: 'Generic CloudTrail Multi-Region', file: filename }
          end
        else
          # Fallback check for any resource with encryption-related properties
          if type.include?('Encrypt') || type.include?('Secure')
            if !resource[:properties].key?('Enabled') && !resource[:properties].key?('enabled')
              gaps << { category: :transmission_protection, rule: "Generic #{type} Encryption", file: filename }
            end
          end
        end
      end

      def parse_regex_based(content, filename)
        controls_found = Hash.new(0)
        gaps = []

        # Use regex to find potential resource patterns
        pattern = /(\w+)\s*:\s*(\w+)/i
        matches = content.scan(pattern).select { |m| m[1].to_s.include?('resource') || m[1].to_s.include?('Resource') }

        matches.each do |match|
          type = match[0] + '.' + match[1]
          
            controls_found[:access_control] += 1
            
              # Check for common security patterns in the content
              if !content.include?('encrypt') && !content.include?('secure') && !content.include?('tls')
                gaps << { category: :transmission_protection, rule: 'Generic Security Configuration', file: filename }
              end

          break unless matches.empty? # Avoid infinite loop
        end

        {
          file: filename,
          resource_count: matches.size,
          controls_found: controls_found.transform_values(&:to_i),
          gaps: gaps
        }
      rescue StandardError => e
        {
          file: filename,
          error: e.message,
          resource_count: 0,
          controls_found: {},
          gaps: [{ category: :access_control, rule: 'Regex Parse Error', file: filename }]
        }
      end

      def calculate_scorecard(all_results)
        total_controls = all_results.values.sum { |r| r[:controls_found].values.sum }
        total_gaps = all_results.values.sum(&:size)

        # Calculate compliance percentage
        compliance_percentage = (total_controls - total_gaps.to_f) / total_controls * 100 rescue 100.0

        # Build scorecard summary
        {
          overall_compliance: format('%.2f', compliance_percentage),
          total_files_scanned: all_results[:total_files],
          files_parsed: all_results[:parsed_files],
          total_controls_found: total_controls,
          total_gaps_identified: total_gaps,
          compliance_level: determine_compliance_level(compliance_percentage),
          category_breakdown: calculate_category_breakdown(all_results),
          top_recommendations: extract_top_recommendations(all_results)
        }
      end

      def determine_compliance_level(percentage)
        if percentage >= 95
          'Excellent'
        elsif percentage >= 80
          'Good'
        elsif percentage >= 60
          'Fair'
        else
          'Needs Improvement'
        end
      end

      def calculate_category_breakdown(all_results)
        category_stats = Hash.new { |h, k| h[k] = { found: 0, gaps: 0 } }

        all_results[:controls_found].each do |category, count|
          next unless count > 0
          
            category_stats[category][:found] += count
            
              # Count gaps per category
              all_results[:gaps].select { |g| g[:category] == category }.each do |gap|
                category_stats[category][:gaps] += 1
              end
        end

        category_stats.transform_values do |stats|
          percentage = stats[:found] > 0 ? (stats[:found] - stats[:gaps].to_f) / stats[:found] * 100 : 100.0
          {
            controls_found: stats[:found],
            gaps_identified: stats[:gaps],
            compliance_percentage: format('%.2f', percentage),
            status: determine_category_status(percentage)
          }
        end