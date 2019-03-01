package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func authBackendResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: authBackendWrite,
		Delete: authBackendDelete,
		Read:   authBackendRead,
		Update: authBackendUpdate,
		Exists: authBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceAuthBackendMigrateState,

		Schema: map[string]*schema.Schema{
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "path to mount the backend. This defaults to the type.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Default lease duration in seconds",
			},

			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration in seconds",
			},

			"audit_non_hmac_request_keys": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of keys that will not be HMAC'd by audit devices in the request data object.",
			},

			"audit_non_hmac_response_keys": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of keys that will not be HMAC'd by audit devices in the response data object.",
			},

			"listing_visibility": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Speficies whether to show this mount in the UI-specific listing endpoint",
			},

			"passthrough_request_headers": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of headers to whitelist and pass from the request to the plugin. ",
			},

			"allowed_response_headers": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of headers to whitelist, allowing a plugin to include them in the response.",
			},

			"local": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "(Vault Enterprise) Specifies if the auth method is local only",
			},

			"seal_wrap": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "(Vault Enterprise) Enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability.",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
		},
	}
}

func authBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountType := d.Get("type").(string)
	path := d.Get("path").(string)

	options := &api.EnableAuthOptions{
		Type:        mountType,
		Description: d.Get("description").(string),
		Config: api.AuthConfigInput{
			DefaultLeaseTTL:           fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:               fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
			AuditNonHMACRequestKeys:   util.ToStringArray(d.Get("audit_non_hmac_request_keys").(*schema.Set).List()),
			AuditNonHMACResponseKeys:  util.ToStringArray(d.Get("audit_non_hmac_response_keys").(*schema.Set).List()),
			ListingVisibility:         d.Get("listing_visibility").(string),
			PassthroughRequestHeaders: util.ToStringArray(d.Get("passthrough_request_headers").(*schema.Set).List()),
		},
		Local: d.Get("local").(bool),
	}

	if path == "" {
		path = mountType
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)

	if err := client.Sys().EnableAuthWithOptions(path, options); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendRead(d, meta)
}

func authBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	if err := client.Sys().DisableAuth(path); err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPath := d.Id() + "/"

	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for path, auth := range auths {
		if path == targetPath {
			d.Set("type", auth.Type)
			d.Set("path", path)
			d.Set("description", auth.Description)
			d.Set("default_lease_ttl_seconds", auth.Config.DefaultLeaseTTL)
			d.Set("max_lease_ttl_seconds", auth.Config.MaxLeaseTTL)
			d.Set("listing_visibility", auth.Config.ListingVisibility)
			d.Set("local", auth.Local)
			d.Set("accessor", auth.Accessor)
			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	d.SetId("")
	return nil
}
